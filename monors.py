#!/usr/bin/env python

# Copyright (c) 2015 Xamarin, Inc (http://www.xamarin.com)
#
# Author:
#  Ludovic Henry (ludovic@xamarin.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
#
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
#
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import os
import sys
import json
import re
import logging
import github
import traceback
from datetime import datetime, MINYEAR

class Comment:
    def __init__(self, login, body, created_at):
        self.login = login
        self.body = body
        self.created_at = created_at

class Status:
    def __init__(self, state, updated_at):
        self.state = state
        self.updated_at = updated_at

class PullReq:
    def __init__(self, cfg, gh, info, reviewers):
        self.cfg = cfg
        self.gh = gh
        self.info = info
        self.reviewers = [r.encode("utf8") for r in reviewers]

        self.dry_run = self.cfg ["dry_run"] is not None

        self.dst_owner = self.cfg ["owner"].encode ("utf8")
        self.dst_repo  = self.cfg ["repo"].encode ("utf8")
        self.dst       = self.gh.repos (self.dst_owner) (self.dst_repo)

        if self.info ["head"]["repo"] is not None:
            self.src_owner = self.info ["head"]["repo"]["owner"]["login"].encode("utf8")
            self.src_repo  = self.info ["head"]["repo"]["name"].encode("utf8")
        else:
            self.src_owner = "unknown owner"
            self.src_repo = "unknown repo"

        self.num = self.info ["number"]
        self.ref = self.info ["head"]["ref"].encode("utf8")
        self.sha = self.info ["head"]["sha"].encode("utf8")

        self.title = self.info ["title"].encode ('utf8') if self.info ["title"] is not None else None
        self.body = self.info ["body"].encode ('utf8') if self.info ["body"] is not None else None

        # TODO: load it from a configuration file?
        self.mandatory_context = [
            "i386 Linux",
            "AMD64 Linux",
            "AMD64 OSX",
        ]

        logging.info ("----- loading %s" % (self.description ()))

        logging.info("loading comments")
        self.comments  = [Comment (self.info ["user"]["login"].encode ("utf8"), self.body, datetime.strptime (self.info ["created_at"], "%Y-%m-%dT%H:%M:%SZ"))] if self.body is not None and len (self.body) > 0 else []
        self.comments += [Comment (comment ["user"]["login"].encode ("utf8"), comment ["body"].encode ('utf8') if comment ["body"] is not None else None, datetime.strptime (comment ["created_at"], "%Y-%m-%dT%H:%M:%SZ"))
            for comment in self.dst.pulls (self.num).comments ().get () + self.dst.issues (self.num).comments ().get ()]

        self.comments = sorted (self.comments, key=lambda c: c.created_at)

    def short(self):
        return "%s/%s/%s = %.8s" % (self.src_owner, self.src_repo, self.ref, self.sha)

    def description(self):
        return "pull https://github.com/%s/%s/pull/%d - %s - '%s'" % (self.dst_owner, self.dst_repo, self.num, self.short(), self.title)

    def add_comment(self, comment):
        if not self.dry_run:
            self.dst.issues (self.num).comments ().post (body=comment)

    def is_mergeable (self):
        if self.info ["mergeable"] is True:
            return True

        if self.info ["mergeable"] is False:
            logging.info ("cannot merge because of conflicts")
        elif self.info ["mergeable"] is None:
            logging.info ("cannot check if mergeable, try again later (see https://developer.github.com/v3/pulls/#response-1)")

        return False

    def has_merge_command (self):
        if self.info ["user"]["login"].encode ("utf8") in self.reviewers and self.info ["title"].lower ().startswith ("[automerge]"):
            return True

        rec = re.compile(r"^@(" + self.cfg ["user"] + "):{0,1} (auto){0,1}merge", re.MULTILINE)
        for c in self.comments:
            if c.login not in self.reviewers:
                logging.debug ("%s: not a reviewer" % (c.login))
                continue

            if re.search(rec, c.body) is None:
                logging.debug ("%s: comment does not match\n%s" % (c.login, c.body))
                continue

            return True

        return False

    def is_successful (self, statuses):
        for context in self.mandatory_context:
            if context not in statuses:
                return None
            if statuses [context].state == "pending":
                return None
            if statuses [context].state != "success":
                return False

        return True

    def try_merge (self):
        if not self.is_mergeable ():
            return

        if not self.has_merge_command ():
            logging.info ("no 'merge' command")
            return

        # structure:
        #  - key: context
        #  - value: Status
        statuses = {}

        logging.info ("loading statuses")
        for status in self.dst.statuses (self.sha).get ():
            if status ["creator"]["login"].encode ("utf8") == self.cfg["user"].encode("utf8"):
                if status ["context"] not in statuses or datetime.strptime (status ["updated_at"], "%Y-%m-%dT%H:%M:%SZ") > statuses [status ["context"]].updated_at:
                    statuses [status ["context"]] = Status (status ["state"].encode ("utf8"), datetime.strptime (status ["updated_at"], "%Y-%m-%dT%H:%M:%SZ"))

        success = self.is_successful (statuses)
        if success is not True:
            message = "cannot merge:"
            comment = message + "\n"
            logging.info (message)

            for context in self.mandatory_context:
                message = " - \"%s\" state is \"%s\"" % (context, statuses [context].state if context in statuses else "pending")
                comment += message + "\n"
                logging.info (message)

            if success is False:
                if len (self.comments) == 0:
                    logging.info ("add 'cannot merge' comment (1)")
                    self.add_comment (comment)
                else:
                    last_comment = None
                    for c in self.comments:
                        if c.login == self.cfg ["user"].encode ("utf8") and c.body.startswith ("cannot merge:".encode ("utf8")) and (last_comment is None or c.created_at > last_comment.created_at):
                            last_comment = c

                    if last_comment is None:
                        logging.info ("add 'cannot merge' comment (2)")
                        self.add_comment (comment)
                    else:
                        last_mandatory_context_update = datetime (MINYEAR, 1, 1, 0, 0, 0, 0)
                        for context in self.mandatory_context:
                            if statuses [context].updated_at > last_mandatory_context_update:
                                last_mandatory_context_update = statuses [context].updated_at

                        if last_mandatory_context_update > last_comment.created_at:
                            logging.info ("add 'cannot merge' comment (3)")
                            self.add_comment (comment)
                        else:
                            logging.info ("discard 'cannot merge' comment, it's already posted")

            return

        try:
            logging.info ("merging successfully, tests results:")
            for context, status in statuses.iteritems ():
                logging.info (" - %s: %s" % (context, status.state))

            message = ""
            message += "%s\n" % (self.title)
            message += "\n"
            if self.body is not None:
                message += "%s\n" % (self.body)

            if not self.dry_run:
                self.dst.pulls(self.num).merge ().put (sha=self.sha, commit_message=message)
        except github.ApiError:
            message = "failed to merge: %s" % (traceback.format_exc ())
            logging.info (message)
            # self.add_comment (message)

def get_collaborators (gh, owner, repo):
    page = 1
    while True:
        collaborators = gh.repos (owner) (repo).collaborators ().get (page=page, per_page=100)
        if len (collaborators) == 0:
            break

        for collaborator in collaborators:
            yield collaborator

        page += 1

def main():
    rfh = logging.StreamHandler (sys.stdout)
    rfh.setFormatter(logging.Formatter(fmt='%(levelname)s - %(message)s', datefmt="%Y-%m-%d %H:%M:%S %Z"))
    rfh.setLevel(logging.INFO)
    logging.root.addHandler(rfh)
    logging.root.setLevel(logging.INFO)

    logging.info("---------- starting run ----------")

    cfg = {
        "owner": os.environ ["MONORS_GH_OWNER"],
        "repo":  os.environ ["MONORS_GH_REPO"],
        "user":  os.environ ["MONORS_GH_USERNAME"],
        "token": os.environ ["MONORS_GH_TOKEN"],
        "dry_run": os.environ.get ("MONORS_DRY_RUN"),
    }

    gh = github.GitHub (username=cfg ["user"], access_token=cfg ["token"])

    reviewers = sorted([collaborator ["login"] for collaborator in get_collaborators (gh, cfg["owner"], cfg["repo"])])
    logging.info("found %d collaborators: %s" % (len (reviewers), ", ".join (reviewers)))

    pulls = gh.repos (cfg["owner"]) (cfg["repo"]).pulls ().get (state="open", sort="updated", direction="desc", per_page = 100)
    logging.info("found %d pull requests", len (pulls))

    pulls = pulls [0:50]
    logging.info("considering %d pull requests", len (pulls))

    for pull in pulls:
        PullReq (cfg, gh, gh.repos (cfg ["owner"]) (cfg ["repo"]).pulls (pull ["number"]).get (), reviewers).try_merge ()

if __name__ == "__main__":
    try:
        main()
    except github.ApiError as e:
        print("Github API exception: " + str(e.response))
        exit(-1)
