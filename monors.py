#!/usr/bin/env python

# Copyright (c) 2015 Xamarin, Inc (http://www.xamarin.com)
#
# Author:
#  Ludovic Henry (ludovic@xamarin.com)
#  Alexander Koeplinger (alexander.koeplinger@xamarin.com)
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

import ast
import os
import sys
import json
import re
import urllib2
import logging
import github
import traceback
from datetime import datetime, MINYEAR
from slacker import Slacker

class Comment:
    def __init__(self, login, body, created_at):
        self.login = login
        self.body = body
        self.created_at = created_at

class Status:
    def __init__(self, state, updated_at, description, target_url):
        self.state = state
        self.updated_at = updated_at
        self.description = description
        self.target_url = target_url

class PullReq:
    def __init__(self, cfg, gh, slack, info, reviewers, gh_to_slack):
        self.cfg = cfg
        self.gh = gh
        self.slack = slack
        self.info = info
        self.reviewers = [r.encode("utf8") for r in reviewers]
        self.gh_to_slack = gh_to_slack

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
        self.id = "%s/%s/pulls/%d" % (self.dst_owner, self.dst_repo, self.num)
        self.ref = self.info ["head"]["ref"].encode("utf8")
        self.sha = self.info ["head"]["sha"].encode("utf8")

        self.title = self.info ["title"].encode ('utf8') if self.info ["title"] is not None else None
        self.body = self.info ["body"].encode ('utf8') if self.info ["body"] is not None else None

        # TODO: load it from a configuration file?
        self.mandatory_context = [
            "Linux i386",
            "Linux x64",
            "OS X i386",
            "OS X x64",
            "Windows i386",
            "Windows x64",
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
        return "pull request https://github.com/%s/%s/pull/%d - %s - '%s'" % (self.dst_owner, self.dst_repo, self.num, self.short(), self.title)

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

    def has_command (self, method):
        if self.info ["user"]["login"].encode ("utf8") in self.reviewers and self.info ["title"].lower ().startswith ("[automerge]"):
            return True

        rec = re.compile(r"^@(" + self.cfg ["user"] + "):{0,1} (auto){0,1}" + method, re.MULTILINE)
        for c in self.comments:
            if c.login not in self.reviewers:
                logging.debug ("%s: not a reviewer" % (c.login))
                continue

            if re.search(rec, c.body) is None:
                logging.debug ("%s: comment does not match\n%s" % (c.login, c.body))
                continue

            return True

        return False

    def has_merge_command (self):
        return self.has_command("merge")

    def has_squash_command (self):
        return self.has_command("squash")

    def has_rebase_command (self):
        return self.has_command("rebase")

    def is_successful (self, statuses):
        # first check that all context are done running
        for context in self.mandatory_context:
            if context not in statuses:
                return None
            if statuses [context].state == "pending":
                return None

        # second check if any context is failed
        for context in self.mandatory_context:
            if statuses [context].state != "success":
                return False

        return True

    def is_done (self, statuses):
        for status in statuses:
            if statuses [status].state == "pending":
                return False

        return True

    def try_merge (self):
        if not self.is_mergeable ():
            return

        method = None
        if self.has_merge_command ():
            method = "merge"
        elif self.has_squash_command ():
            method = "squash"
        elif self.has_rebase_command ():
            method = "rebase"

        if not method:
            logging.info ("no 'merge', 'squash' or 'rebase' command")
            return

        # structure:
        #  - key: context
        #  - value: Status
        statuses = {}

        logging.info ("loading statuses")
        for status in self.dst.statuses (self.sha).get ():
            if status ["creator"]["login"].encode ("utf8") == self.cfg["user"].encode("utf8"):
                if status ["context"] not in statuses or datetime.strptime (status ["updated_at"], "%Y-%m-%dT%H:%M:%SZ") > statuses [status ["context"]].updated_at:
                    statuses [status ["context"]] = Status (status ["state"].encode ("utf8"), datetime.strptime (status ["updated_at"], "%Y-%m-%dT%H:%M:%SZ"), status["description"], status["target_url"])

        success = self.is_successful (statuses)
        if success is not True:
            message = "cannot " + method + ":"
            comment = message + "\n"
            logging.info (message)

            for context in self.mandatory_context:
                message = " - \"%s\" state is \"%s\"" % (context, statuses [context].state if context in statuses else "pending")
                comment += message + "\n"
                logging.info (message)

            if success is False:
                if len (self.comments) == 0:
                    logging.info ("add 'cannot " + method + "' comment (1)")
                    self.add_comment (comment)
                else:
                    last_comment = None
                    for c in self.comments:
                        if c.login == self.cfg ["user"].encode ("utf8") and c.body.startswith ("cannot " + method + ":".encode ("utf8")) and (last_comment is None or c.created_at > last_comment.created_at):
                            last_comment = c

                    if last_comment is None:
                        logging.info ("add 'cannot " + method + "' comment (2)")
                        self.add_comment (comment)
                    else:
                        last_mandatory_context_update = datetime (MINYEAR, 1, 1, 0, 0, 0, 0)
                        for context in self.mandatory_context:
                            if statuses [context].updated_at > last_mandatory_context_update:
                                last_mandatory_context_update = statuses [context].updated_at

                        if last_mandatory_context_update > last_comment.created_at:
                            logging.info ("add 'cannot " + method + "' comment (3)")
                            self.add_comment (comment)
                        else:
                            logging.info ("discard 'cannot " + method + "' comment, it's already posted")

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
                self.dst.pulls(self.num).merge ().put (sha=self.sha, commit_message=message, merge_method=method)
        except github.ApiError:
            message = "failed to merge: %s" % (traceback.format_exc ())
            logging.info (message)
            # self.add_comment (message)

    def already_sent_message_for_pr (self, history):
        if not self.id in history or history[self.id]["last_seen_sha"] != self.sha:
          return False

        # TODO: refactor/deduplicate this with below
        # structure:
        #  - key: context
        #  - value: Status
        statuses = {}

        logging.info ("loading statuses")
        for status in self.dst.statuses (self.sha).get ():
          if status ["context"] not in statuses or datetime.strptime (status ["updated_at"], "%Y-%m-%dT%H:%M:%SZ") > statuses [status ["context"]].updated_at:
            statuses [status ["context"]] = Status (status ["state"].encode ("utf8"), datetime.strptime (status ["updated_at"], "%Y-%m-%dT%H:%M:%SZ"), status["description"], status["target_url"])

        for context, status in sorted (statuses.iteritems ()):
          if not context in history[self.id]["last_seen_status"]:
            return False
          if status.updated_at.isoformat () != history[self.id]["last_seen_status"][context]["updated_at"]:
            return False

        return True

    def fetch_failure_reasons (self, target_url):
        result = self.fetch_failure_reasons_babysitter (target_url)

        if result is None:
          result = self.fetch_failure_reasons_failure_analyzer_plugin (target_url)

        return result

    def fetch_failure_reasons_babysitter (self, target_url):
        try:
          babysitter_blob = None
          response = ast.literal_eval (urllib2.urlopen ("%s/Azure/api/python?tree=individualBlobs[blobURL]" % target_url).read())

          for blob in response["individualBlobs"]:
            if blob["blobURL"].endswith("babysitter_report.json_lines"):
              babysitter_blob = urllib2.urlopen (blob["blobURL"]).read()

          if babysitter_blob is None:
            return None

          message = ""
          tests = ""
          for line in filter (None, babysitter_blob.split ('\n')):
            invocation = json.loads (line)
            if invocation["final_code"] != 0:
               message += "Exit code %s in step \"%s\"\n" % (invocation["final_code"], invocation["invocation"])
               if "tests" in invocation:
                 for test in invocation["tests"]:
                   tests += "\t%s\n" % test

          if tests == "":
            return message
          else:
            return "%s\nFailed Tests:\n%s" % (message, tests)
        except Exception:
          return None

    def fetch_failure_reasons_failure_analyzer_plugin (self, target_url):
        try:
          message = ""
          issueIndex = 1
          response = ast.literal_eval (urllib2.urlopen ("%s/api/python?tree=actions[foundFailureCauses[*]]" % target_url).read())
          for action in response["actions"]:
            if "_class" in action and action["_class"] == "com.sonyericsson.jenkins.plugins.bfa.model.FailureCauseBuildAction":
              for cause in action["foundFailureCauses"]:
                message += "Issue %s: %s:\n\t%s\n\n" % (issueIndex, cause["name"], cause["description"])
                issueIndex += 1

          return message
        except Exception:
          return None

    def try_slack (self):
        logging.info ("Processing Slack notifications")

        history = json.load (open ("monors_slack_history.json"))

        if self.already_sent_message_for_pr (history):
          logging.info ("Already sent Slack message for latest statuses in PR %d and sha %s, skipping." % (self.num, self.sha))
          return

        logging.info ("sha not seen on PR %d yet: %s" % (self.num, self.sha))

        gh_user = self.info ["user"]["login"].encode ("utf8")
        if not gh_user in self.gh_to_slack:
          logging.info ("Couldn't find %s in the GitHub<->Slack user mapping file, skipping." % gh_user)
          return

        slack_user = self.gh_to_slack[gh_user]
        logging.info ("Mapped GitHub user %s to Slack user %s." % (gh_user, slack_user))

        # structure:
        #  - key: context
        #  - value: Status
        statuses = {}

        logging.info ("loading statuses")
        for status in self.dst.statuses (self.sha).get ():
          if status ["context"] not in statuses or datetime.strptime (status ["updated_at"], "%Y-%m-%dT%H:%M:%SZ") > statuses [status ["context"]].updated_at:
            statuses [status ["context"]] = Status (status ["state"].encode ("utf8"), datetime.strptime (status ["updated_at"], "%Y-%m-%dT%H:%M:%SZ"), status["description"], status["target_url"])

        done = self.is_done (statuses)
        if not done:
          logging.info ("PR builds are not done yet, skipping.")
          return

        message = "Build results for PR#%d - <https://github.com/%s/%s/pull/%d|%s>\n" % (self.num, self.dst_owner, self.dst_repo, self.num, self.title)

        attachments = []

        for context, status in sorted (statuses.iteritems ()):
          att = {}
          att["fallback"] = "%s *%s*: %s" % (status.state, context, status.description)
          att["text"] = "*<%s|%s>*: %s" % (status.target_url, context, status.description) if status.target_url else "*%s*: %s" % (context, status.description)
          att["footer"] = self.fetch_failure_reasons (status.target_url) if status.state != "success" else None
          if status.state == "success":
            att["color"] = "good"
          elif status.state == "pending":
            att["color"] = "#ffee58"
          elif " 0 failed." in status.description:
            att["color"] = "#f57f17"
          elif " 1 failed." in status.description:
            att["color"] = "#f57f17"
          elif " 2 failed." in status.description:
            att["color"] = "#f57f17"
          else:
            att["color"] = "#bf360c"
          att["mrkdwn_in"] = ["text"]
          attachments.append (att)

        if not self.id in history:
          history[self.id] = {}

        history[self.id]["last_seen_sha"] = self.sha
        history[self.id]["last_seen_status"] = {}

        for context, status in sorted (statuses.iteritems ()):
          history[self.id]["last_seen_status"][context] = {}
          history[self.id]["last_seen_status"][context]["state"] = status.state
          history[self.id]["last_seen_status"][context]["updated_at"] = status.updated_at.isoformat ()

        if not self.dry_run:
          # write to file before sending so a send error doesn't cause an infinite send-fail-send loop
          json.dump (history, open ("monors_slack_history.json", "w"), indent = 2, sort_keys = True)

          self.slack.chat.post_message (channel="@%s" % slack_user, text=message, as_user="true", unfurl_links="false", attachments=attachments)

          logging.info ("Sent Slack notification to %s" % slack_user)
        else:
          logging.info ("Dry-run, not sending Slack message.")

        return

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
        "slacktoken": os.environ ["MONORS_SL_TOKEN"],
        "dry_run": os.environ.get ("MONORS_DRY_RUN"),
    }

    gh = github.GitHub (username=cfg ["user"], access_token=cfg ["token"])
    slack = Slacker (cfg ["slacktoken"])

    rl = gh.rate_limit.get () # test authentication and rate limit
    logging.info ("Remaining GitHub API calls before reaching limit: %d, resets at %s." % (rl["rate"]["remaining"], datetime.fromtimestamp(rl["rate"]["reset"])))

    gh_slack_usermapping = json.load(open("monors_slack_users.json"))

    reviewers = sorted([collaborator ["login"] for collaborator in get_collaborators (gh, cfg["owner"], cfg["repo"])])
    logging.info("found %d collaborators: %s" % (len (reviewers), ", ".join (reviewers)))

    pulls = gh.repos (cfg["owner"]) (cfg["repo"]).pulls ().get (state="open", sort="updated", direction="desc", per_page = 100)
    logging.info("found %d pull requests", len (pulls))

    pulls = pulls [0:50]
    logging.info("considering %d pull requests", len (pulls))

    for pull in pulls:
        pr = PullReq (cfg, gh, slack, gh.repos (cfg ["owner"]) (cfg ["repo"]).pulls (pull ["number"]).get (), reviewers, gh_slack_usermapping)
        pr.try_merge ()
        pr.try_slack ()

if __name__ == "__main__":
    try:
        main()
    except github.ApiError as e:
        print("Github API exception: " + str(e.response))
        exit(-1)
