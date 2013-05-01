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
import tornado.auth
import tornado.escape
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import json
import urlparse
import urllib
import httplib2

from tornado.options import define, options

define("port", default=os.environ['PORT'], help="run on the given port", type=int)


# production env

define("facebook_api_key", help="your Facebook application API key",
       default="423582524399775")
define("facebook_secret", help="your Facebook application secret",
       default="c535d19c6d09c007e17aaa3fdc5768c4")
"""
# test env
define("facebook_api_key", help="your Facebook application API key",
       default="443987802343405")
define("facebook_secret", help="your Facebook application secret",
       default="c0ebc99f35e9142694eeeb95a37aeb76")
"""
class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", Main2Handler),
            (r"/main", MainHandler),
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
            ui_modules={"Post": PostModule},
            debug=True,
            autoescape=None,
        )
        tornado.web.Application.__init__(self, handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        user_json = self.get_secure_cookie("user")
        if not user_json: return None
        return tornado.escape.json_decode(user_json)


class Main2Handler(BaseHandler):
    def get(self):
        self.render("index.html",isLogin=(self.get_current_user()!=None))

class FqlReporterHandler(BaseHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def get(self):
        #query = tornado.escape.url_escape('{"post_ids":"SELECT post_id FROM stream WHERE source_id=me() AND likes.count>0 LIMIT 5000",' + \
        #        '"like_ids":"SELECT name,sex FROM user WHERE uid IN (SELECT user_id FROM like WHERE post_id IN (SELECT post_id FROM #post_ids))"}')
        query = '{"post_ids":"SELECT post_id FROM stream WHERE source_id=me() AND likes.count>0 LIMIT 5000",' + \
                '"uids":"SELECT user_id FROM like WHERE post_id IN (SELECT post_id FROM #post_ids)",' +\
                '"like_ids":"SELECT name,sex,uid FROM user WHERE uid IN (SELECT user_id FROM #uids)"}'
        self.facebook_request("/fql", self._handle_result,
                              access_token=self.current_user["access_token"],
                              q=query)
        self.o = {'name':'likes' , 'children':[ {'name':'女性','children':[]} ,  {'name':'男性','children':[]}  ]}
        self.set_header('Content-Type', 'application/json')

    def _handle_result(self, r):
        if r is None:
            self._output()
        else:
            m_r = {}
            f_r = {}
            rr = {}
            for p in r['data'][1]['fql_result_set']:
                fid = p['user_id']
                if fid in rr:
                    rr[fid] = rr[fid] + 1
                else:
                    rr[fid] = 1

            for u in rr:
                size = rr[u]
                if size >5:
                    user = self._get_user_info(r['data'][2]['fql_result_set'],u)
                    if user is None:
                        pass
                    else:
                        if user['sex'] == 'female':
                            self.o['children'][0]['children'].append({'name':user['name'] , 'size':size})        
                        else:
                            self.o['children'][1]['children'].append({'name':user['name'] , 'size':size})
            self._output()

    def _get_user_info(self,user_json,uid):
        for j in user_json:
            if j['uid'] == uid:
                return j
        return None

    def _output(self):
        self.write(tornado.escape.json_encode(self.o))
        self.finish()

class ReporterHandler(BaseHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def get(self):
        print "[debug] user = " + str(self.current_user) 
        self.facebook_request("/me/posts", self._on_like,
                              access_token=self.current_user["access_token"])
        self.o = {'name':'likes' , 'children':[]}
        self.set_header('Content-Type', 'application/json')

        self.limit = 6
        self.count = 0

    def _get_url_param(self,url,key):
        parsed = urlparse.urlparse(url)
        return urlparse.parse_qs(parsed.query)[key]

    def __get_fb_name(self,id):
        http = httplib2.Http()
        url = 'https://graph.facebook.com/'+id+'?method=GET&format=json&access_token='+self.current_user["access_token"]
        print "[get fb name ] url " + url
        response, content = http.request(url, 'GET')
        jj = tornado.escape.json_decode(content)
        return jj['name']

    def _trans_name(self,jn):
        for j in jn['children']:
            j['name'] = self.__get_fb_name(j['id'])

    def _output(self):
        # todo id transfer to name 
        #self._trans_name(self.o)
        self.write(tornado.escape.json_encode(self.o))
        self.finish()

    def _on_like(self,likes):
        if likes is None:
            self._output()
        else:
            if self.count >= self.limit:
                self._output()
            else:
                r = {}
                print "[on like] size " + str(len(likes["data"]))
                for p in likes["data"]:
                    if p.get('likes',None) != None:
                        for l in p["likes"]["data"]:
                            fid = int(l["id"])
                            if fid in r:
                                r[fid] = r[fid] +1
                            else:
                                r[fid] = 1
                for k in r:
                    self.o["children"].append({'name':k , 'size':r[k]})

                self.count = self.count+1

                next = likes["paging"].get('next',None)
                print "[PAGING] next = " + next 
                if next != None:
                    http = httplib2.Http()
                    response, content = http.request(next, 'GET')
                    print "[PAGING] result " + str(response) 
                    self._on_like(tornado.escape.json_decode(content))
                else:
                    self._output()

class MainHandler(BaseHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def get(self):
        #print "[debug] user = " + str(self.current_user) 
        #self.facebook_request("/me/home", self._on_stream,
        self.facebook_request("/me/posts", self.async_callback(self._on_like),
                              access_token=self.current_user["access_token"])
        #self._on_like()

    def _on_like(self,likes):
        #print "get likes : " + str(likes)
        if likes is None:
            self.redirect("/auth/login")
            return
        self.render("likes.html") 

    def _on_stream(self, stream):
        if stream is None:
            # Session may have expired
            self.redirect("/auth/login")
            return
        self.render("stream.html", stream=stream)


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


class PostModule(tornado.web.UIModule):
    def render(self, post):
        return self.render_string("modules/post.html", post=post)


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
