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
import time

class PullReq:
    def __init__(self, cfg, gh, pull, reviewers):
        self.cfg = cfg
        self.gh = gh
        self.pull = pull
        self.reviewers = [r.encode("utf8") for r in reviewers]

        self.dry_run = self.cfg ["dry_run"] is not None

        self.dst_owner = self.cfg ["owner"].encode ("utf8")
        self.dst_repo  = self.cfg ["repo"].encode ("utf8")
        self.dst       = self.gh.repos (self.dst_owner) (self.dst_repo)

        self.src_owner = self.pull ["head"]["repo"]["owner"]["login"].encode("utf8")
        self.src_repo  = self.pull ["head"]["repo"]["name"].encode("utf8")

        self.num = self.pull ["number"]
        self.ref = self.pull ["head"]["ref"].encode("utf8")
        self.sha = self.pull ["head"]["sha"].encode("utf8")

        self.title = self.pull ["title"].encode ('utf8') if self.pull ["title"] is not None else None
        self.body = self.pull ["body"].encode ('utf8') if self.pull ["body"] is not None else None

        # TODO: load it from a configuration file?
        self.mandatory_context = [
            "i386 Linux",
            "AMD64 Linux",
        ]

    def short(self):
        return "%s/%s/%s = %.8s" % (self.src_owner, self.src_repo, self.ref, self.sha)

    def description(self):
        return "pull https://github.com/%s/%s/pull/%d - %s - '%s'" % (self.dst_owner, self.dst_repo, self.num, self.short(), self.title)

    def add_comment(self, comment):
        if not self.dry_run:
            self.dst.commits (self.sha).comments ().post (body=comment)

    def is_mergeable (self, info):
        if info ["mergeable"] is True:
            return True

        if info ["mergeable"] is False:
            logging.info ("cannot merge because of conflicts")
        elif info ["mergeable"] is None:
            logging.info ("cannot check if mergeable, try again later (see https://developer.github.com/v3/pulls/#response-1)")

        return False

    def has_merge_command (self, info, comments):
        if info ["user"]["login"].encode ("utf8") in self.reviewers and info ["title"].lower ().startswith ("[automerge]"):
            return True

        rec = re.compile(r"^@(?:" + self.cfg ["user"] + "):{0,1} (auto){0,1}merge", re.MULTILINE)
        for (_, user, comment) in comments:
            if user in self.reviewers and re.match(rec, comment) is not None:
                return True

        return False

    def is_successful (self, statuses):
        for context in self.mandatory_context:
            if context not in statuses:
                return None
            if statuses [context][0] == "pending":
                return None
            if statuses [context][0] != "success":
                return False

        return True

    def try_merge (self):
        logging.info ("----- trying to merge %s" % (self.description ()))

        logging.info ("loading info")
        info = self.dst.pulls (self.num).get ()

        if not self.is_mergeable (info):
            return

        logging.info("loading comments")
        comments  = [(info ["created_at"].encode ("utf8"), info ["user"]["login"].encode ("utf8"), self.body)] if self.body is not None else []
        comments += [(comment ["created_at"].encode ("utf8"), comment ["user"]["login"].encode ("utf8"), comment ["body"].encode ('utf8') if comment ["body"] is not None else None)
            for comment in self.dst.pulls (self.num).comments ().get () + self.dst.issues (self.num).comments ().get ()]

        if not self.has_merge_command (info, comments):
            logging.info ("no 'merge' command")
            return

        # structure:
        #  - key: context
        #  - value: tuple
        #   - 0: state (pending/success/failure/error)
        #   - 1: date
        statuses = {}

        logging.info ("loading statuses")
        for status in self.dst.statuses (self.sha).get ():
            if status ["creator"]["login"].encode ("utf8") == self.cfg["user"].encode("utf8"):
                if status ["context"] not in statuses \
                        or time.strptime (status ["updated_at"], "%Y-%m-%dT%H:%M:%SZ") > time.strptime (statuses [status ["context"]][1], "%Y-%m-%dT%H:%M:%SZ"):
                    statuses [status ["context"]] = (
                        status ["state"].encode ("utf8"),
                        status ["updated_at"],
                    )

        success = self.is_successful (statuses)
        if success is not True:
            message = "cannot merge:"
            comment = message
            logging.info (message)

            for context in self.mandatory_context:
                message = " - \"%s\" state is \"%s\"" % (context, statuses [context][0] if context in statuses else "pending")
                comment += message
                logging.info (message)

            if success is False:
                if len (comments) == 0:
                    self.add_comment (comment)

                (_, user, comment) = comments [-1]
                if not user is self.cfg ["user"].encode ("utf8") or not comment.startswith ("cannot merge:".encode ("utf8")):
                    self.add_comment (comment)

            return

        try:
            logging.info ("merging successfully, tests results:")
            for context, status in statuses.iteritems ():
                logging.info (" - %s: %s" % (context, status [0]))

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
            self.add_comment (message)

def main():
    rfh = logging.StreamHandler (sys.stdout)
    rfh.setFormatter(logging.Formatter(fmt='%(levelname)s - %(message)s', datefmt="%Y-%m-%d %H:%M:%S %Z"))
    rfh.setLevel(logging.DEBUG)
    logging.root.addHandler(rfh)
    logging.root.setLevel(logging.DEBUG)

    logging.info("---------- starting run ----------")

    cfg = {
        "owner": os.environ ["MONORS_GH_OWNER"],
        "repo":  os.environ ["MONORS_GH_REPO"],
        "user":  os.environ ["MONORS_GH_USERNAME"],
        "token": os.environ ["MONORS_GH_TOKEN"],
        "dry_run": os.environ.get ("MONORS_DRY_RUN"),
    }

    gh = github.GitHub (username=cfg ["user"], access_token=cfg ["token"])

    reviewers = [collaborator ["login"] for collaborator in gh.repos(cfg["owner"])(cfg["repo"]).collaborators().get()] + ["ludovic-henry"]
    logging.info("found %d collaborators: %s" % (len (reviewers), ", ".join (reviewers)))

    pulls = gh.repos (cfg["owner"]) (cfg["repo"]).pulls ().get (state="open", sort="updated", direction="desc")
    logging.info("found %d pull requests", len (pulls))

    pulls = pulls [0:25]
    logging.info("considering %d pull requests", len (pulls))

    for pull in pulls:
        PullReq (cfg, gh, pull, reviewers).try_merge ()

if __name__ == "__main__":
    try:
        main()
    except github.ApiError as e:
        print("Github API exception: " + str(e.response))
        exit(-1)
