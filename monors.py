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
    def __init__(self, cfg, gh, pull):
        self.cfg = cfg
        self.gh = gh
        self.pull = pull

        self.reviewers = [r.encode("utf8") for r in self.cfg["reviewers"]]

        self.dst_owner = self.cfg ["owner"].encode ("utf8")
        self.dst_repo  = self.cfg ["repo"].encode ("utf8")
        self.dst       = self.gh.repos (self.dst_owner) (self.dst_repo)

        self.src_owner = self.pull ["head"]["repo"]["owner"]["login"].encode("utf8")
        self.src_repo  = self.pull ["head"]["repo"]["name"].encode("utf8")

        self.num = self.pull ["number"]
        self.ref = self.pull ["head"]["ref"].encode("utf8")
        self.sha = self.pull ["head"]["sha"].encode("utf8")

        self.title = self.pull ["title"].encode ('utf8') if self.pull ["title"] is not None else None

    def short(self):
        return "%s/%s/%s = %.8s" % (self.src_owner, self.src_repo, self.ref, self.sha)

    def description(self):
        return "pull https://github.com/%s/%s/pull/%d - %s - '%s'" % (self.dst_owner, self.dst_repo, self.num, self.short(), self.title)

    def add_comment(self, comment):
        self.dst.commits (self.sha).comments ().post (body=comment)

    def merge (self, comment):
        self.dst.pulls(self.num).merge ().put (sha=self.sha, commit_message=comment)

    def has_merge_command (self, comments):
        regex = r"^@(?:" + self.cfg ["user"] + "):{0,1} merge"
        rec = re.compile(regex)
        for (_, user, comment) in comments:
            if user in self.reviewers and re.match(rec, comment) is not None:
                return True

        return False

    def is_status_mandatory (self, context):
        # TODO: maybe load it from a configuration file?
        return context in [
            "i386 Linux",
            "AMD64 Linux",
        ]

    def check_statuses_for_success (self, statuses, comments):
        success = True
        pending = False

        failure_comment = ""

        for context, status in statuses.iteritems ():
            if status [0] != "success" and self.is_status_mandatory (context):

                if success:
                    message = "cannot merge:"
                    failure_comment += message
                    logging.info (message)

                message = " - \"%s\" state is \"%s\"" % (context, status [0])
                failure_comment += message
                logging.info (message)

                success = False
                if status [0] == "pending":
                    pending = True

        if not success and not pending:
            (_, user, comment) = comments [-1]
            if not user is self.cfg ["user"].encode ("utf8") or not comment.startswith ("cannot merge:".encode ("utf8")):
                self.add_comment (failure_comment)

        return success

    def try_merge (self):
        logging.info ("----- trying to merge %s" % (self.description ()))

        logging.info ("loading info")
        pull = self.dst.pulls (self.num).get ()

        if pull ["mergeable"] == False:
            logging.info ("cannot merge because of conflicts")
            return
        elif pull ["mergeable"] == None:
            logging.info ("cannot check if mergeable, try again later (see https://developer.github.com/v3/pulls/#response-1)")
            return

        comments = []

        logging.info("loading comments")
        for comment in self.dst.pulls (self.num).comments ().get () + self.dst.issues (self.num).comments ().get ():
            comments.append (
                (
                    comment ["created_at"].encode ("utf8"),
                    comment ["user"]["login"].encode ("utf8"),
                    comment ["body"].encode ('utf8') if comment ["body"] is not None else None
                )
            )

        if not self.has_merge_command (comments):
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

        if not self.check_statuses_for_success (statuses, comments):
            return

        try:
            logging.info ("merging successfully, tests results:")
            for context, status in statuses.iteritems ():
                logging.info (" - %s: %s" % (context, status [0]))

            message = "Merge pull request #%d from %s/%s\n" % (self.num, self.src_owner, self.ref)
            message += "\n"
            message += "%s\n" % (self.title)
            message += "\n"
            # message += "Reviewed-by: %s" % (",".join (self.approval_list()))
            # message += "\n"
            message += "Tests results:\n"
            for context, status in statuses.iteritems ():
                message += " - %s: %s\n" % (context, status [0])

            self.merge (message)
            self.add_comment (message)
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
    }

    gh = github.GitHub (username=cfg ["user"], access_token=cfg ["token"])

    cfg ["reviewers"] = [collaborator ["login"] for collaborator in gh.repos(cfg["owner"])(cfg["repo"]).collaborators().get()] + ["ludovic-henry"]
    logging.info("found %d collaborators: %s" % (len (cfg ["reviewers"]), ", ".join (cfg ["reviewers"])))

    pulls = gh.repos (cfg["owner"]) (cfg["repo"]).pulls ().get (state="open", sort="updated", direction="desc")
    logging.info("found %d pull requests", len (pulls))

    pulls = pulls [0:25]
    logging.info("considering %d pull requests", len (pulls))

    for pull in pulls:
        PullReq (cfg, gh, pull).try_merge ()

if __name__ == "__main__":
    try:
        main()
    except github.ApiError as e:
        print("Github API exception: " + str(e.response))
        exit(-1)
