#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os.path
import os
import tornado.auth
import tornado.escape
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.autoreload
import json
import urlparse
import urllib
import httplib2
import pymongo
import datetime
from pymongo import MongoClient
import copy


from tornado.options import define, options

define("port", default=os.environ['PORT'], help="run on the given port", type=int)

# example : mongodb://USERNAME:PASSWORD@DOMAIN:PORT/COLLECTION
MONGO_URL =''

define("facebook_api_key", help="your Facebook application API key",
       default="YOUR_FACEBOOK_API_KEY")
define("facebook_secret", help="your Facebook application secret",
       default="YOUR_FACEBOOK_API_SECRECT")

conn = pymongo.Connection(MONGO_URL)
db = conn['YOUR_MONGO_COLLECTION']
user_log = db.user_log_test

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/locki", FqlReporterHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
        ]
        settings = dict(
            cookie_secret="__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url="/auth/login",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
            facebook_api_key=options.facebook_api_key,
            facebook_secret=options.facebook_secret,
            debug=True,
            autoescape=None,
        )

        for (path, dirs, files) in os.walk(settings["template_path"]):
            for item in files:
                tornado.autoreload.watch(os.path.join(path, item))

        tornado.web.Application.__init__(self, handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user_json = self.get_secure_cookie("user")
        if not user_json: return None
        return tornado.escape.json_decode(user_json)


class MainHandler(BaseHandler):
    def get(self):
        self.render("index.html",isLogin=(self.get_current_user()!=None))

class FqlReporterHandler(BaseHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def get(self):
        print "fql start"
        q = "select message,description,likes.count,comment_info.comment_count, permalink,created_time from stream where source_id=me() and actor_id=me() and likes.can_like=1 limit 5000"
        self.facebook_request("/fql", self._handle_result, q=q, access_token=self.current_user["access_token"])
        self.op = {"timeline":[],"max":[]}
        self.set_header('Content-Type', 'application/json')

    def __get_content(self, p):
        r = ""
        if p['description'] != None:
            r = r + p['description']
        if p['message'] != None:
            r = r + p['message']
        return r

    def _handle_result(self, r):
        if r is None:
            self._output()
        else:
            timeline=[]
            for p in r['data']:
                timeline.append({'t' :p['created_time'] ,
                                'lc':p['likes']['count'],
                                'cc':p['comment_info']['comment_count'],
                                'l' :p['permalink'],
                                'c' :self.__get_content(p)})
            self.op['timeline'] = sorted(timeline, key=lambda k: k['t'])

            timeline_list = copy.copy(self.op["timeline"])
            d = sorted(timeline_list, key=lambda k: k['lc'],reverse=True)
            for i in range(0,10):
                self.op["max"].append(d[i])
            log = { "user": self.current_user,
                    "result": self.op["max"],
                    "date": datetime.datetime.utcnow()}
            log_id = user_log.insert(log)
            self._output()

    def _output(self):
        self.write(tornado.escape.json_encode(self.op))
        self.finish()

class AuthLoginHandler(BaseHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.asynchronous
    def get(self):
        my_url = (self.request.protocol + "://" + self.request.host +
                  "/auth/login?next=" +
                  tornado.escape.url_escape(self.get_argument("next", "/")))
        if self.get_argument("code", False):
            self.get_authenticated_user(
                redirect_uri=my_url,
                client_id=self.settings["facebook_api_key"],
                client_secret=self.settings["facebook_secret"],
                code=self.get_argument("code"),
                callback=self._on_auth)
            return
        self.authorize_redirect(redirect_uri=my_url,
                                client_id=self.settings["facebook_api_key"],
                                extra_params={"scope": "read_stream"})

    def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(500, "Facebook auth failed")
        self.set_secure_cookie("user", tornado.escape.json_encode(user))
        self.redirect(self.get_argument("next", "/"))


class AuthLogoutHandler(BaseHandler, tornado.auth.FacebookGraphMixin):
    def get(self):
        self.clear_cookie("user")
        self.redirect(self.get_argument("next", "/"))


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()

