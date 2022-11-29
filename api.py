#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from datetime import datetime
import hashlib
import uuid
from optparse import OptionParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from logger_config import logger
from scoring import get_score, get_interests
from store import StoreConnect

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Inition():
    def __init__(self, required, nullable):
        self.nullable = nullable
        self.required = required

    def __set_name__(self, owner, name):
        self.name = name

    def __set__(self, instance, value):
        if self.verify_required(value):
            value = self.verify(value)
            if instance.__class__.__name__ == "OnlineScoreRequest":
                instance.has.append(self.name)
        instance.__dict__[self.name] = value

    def verify_required(self, arg):
        if self.required and arg is None:
            raise ValueError(f'{self.name} field is required!')
        if not self.nullable and not str(arg).strip("[]{}""''()"):
            raise ValueError(f'{self.name} is not nullable')
        return False if self.nullable and \
            (not str(arg).strip("[]{}""''()") or arg is None) else True


class CharField(Inition):
    def verify(self, arg):
        if type(arg) != str:
            raise TypeError(f"{self.name}:{arg} is not string")
        else:
            return arg


class ArgumentsField(Inition):
    @staticmethod
    def verify(arg: dict):
        if not isinstance(arg, dict):
            raise TypeError(f'argument: {arg} is not valid json')
        try:
            dump = json.dumps(arg)
            json.loads(dump)
            return arg
        except TypeError:
            raise TypeError(f'argument: {arg} is not valid json')


class EmailField(Inition):
    @staticmethod
    def verify(arg):
        if "@" not in arg:
            raise TypeError(f"email: {arg} is not valid email")
        else:
            return arg


class PhoneField(Inition):
    @staticmethod
    def verify(arg):
        arg = str(arg)
        if not (arg.isdigit() and len(arg) == 11 and arg[:1] == "7"):
            raise TypeError(f"phone: {arg} is not valid phone")
        else:
            return arg


class DateField(Inition):
    @staticmethod
    def verify(arg):
        try:
            datetime.strptime(arg, '%d.%m.%Y')
            return arg
        except ValueError:
            raise ValueError(f"date: date {arg} is not valid format")


class BirthDayField(Inition):
    @staticmethod
    def verify(arg):
        try:
            delta = datetime.now() - datetime.strptime(arg, '%d.%m.%Y')
        except ValueError:
            raise ValueError(f"brithday: field {arg} is not valid format")
        if not delta.days / 365 < 70:
            raise ValueError("brithday: age > 70 years")
        else:
            return arg


class GenderField(Inition):
    @staticmethod
    def verify(arg):
        if str(arg).strip("012") or type(arg) != int:
            raise ValueError("gender: not valid")
        else:
            return arg


class ClientIDsField(Inition):
    @staticmethod
    def verify(arg):
        if type(arg) != list or not str(arg).strip("[]"):
            raise TypeError(f"client_id: {arg} is not valid")
        elif len(list(filter(lambda x: type(x) is not int, arg))) > 0:
            raise TypeError(f"client_id: {arg} is not valid")
        else:
            return arg


class Meta(type):
    def collect_attrs(cls):
        for key, value in cls.attrs.items():
            if issubclass(value.__class__, Inition):
                cls.field.append(key)

    def __init__(cls, name, base, attrs):
        cls.attrs = attrs
        cls.field = []
        cls.collect_attrs()
        super().__init__(name, base, attrs)


class InitRequest(metaclass=Meta):
    def __init__(self, req):
        self.req = req
        self.has = []
        try:
            self.response = self.init_attrs()
        except ValueError as e:
            self.response = str(e), 422

    def init_attrs(self):
        try:
            for key in self.field:
                setattr(self, key, self.req.get(key))
        except TypeError or ValueError as e:
            return str(e), 422

    def make_request(self, req):
        for key, value in req.items():
            self.req[key] = self.__dict__[key]


class ClientsInterestsRequest(InitRequest):
    client_ids: list = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(InitRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)


class MethodRequest(InitRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=True)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(
            (datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode()
        ).hexdigest()
    else:
        digest = hashlib.sha512(
            (request.account + request.login + SALT).encode()
        ).hexdigest()
    if digest == request.token:
        return True
    return False


def online_score_method(request, login, context, store):
    online_sc = OnlineScoreRequest(req=request["body"]["arguments"])
    if online_sc.response:
        return online_sc.response
    if ((online_sc.phone and online_sc.email) is None) and (
            (online_sc.first_name and online_sc.last_name) is None) and (
            (online_sc.gender and online_sc.birthday) is None):
        return "Not null pairs phone-email," \
               " first name-last name,gender-birthday", 422
    context["has"] = online_sc.has
    if login == "admin":
        return {"score": 42}, OK
    score = get_score(store=store,
                      phone=online_sc.phone,
                      email=online_sc.email,
                      birthday=online_sc.birthday,
                      gender=online_sc.gender,
                      first_name=online_sc.first_name,
                      last_name=online_sc.last_name,
                      )
    return {"score": score}, OK


def interests_request(request, context, store):
    interests = {}
    clients_interests = ClientsInterestsRequest(
        req=request["body"]["arguments"]
    )
    if clients_interests.response:
        return clients_interests.response
    context["nclients"] = len(clients_interests.client_ids)
    for i in clients_interests.client_ids:
        interests[i] = get_interests(store, i)
    return interests, 200


def method_handler(request, ctx, store):
    if request["body"] == {}:
        return ERRORS[422], 422
    request_method = MethodRequest(req=request["body"])
    if request_method.response:
        return request_method.response
    if not check_auth(request_method):
        return ERRORS[403], FORBIDDEN
    if request["body"]["method"] == "online_score":
        return online_score_method(request, request_method.login, ctx, store)
    if request["body"]['method'] == "clients_interests":
        return interests_request(request, ctx, store)


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = StoreConnect(host='localhost', port=6379, db=0)

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except Exception as e:
            logger.exception('Error, bad request', e)
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logger.info(
                "%s: %s %s" % (self.path, data_string, context["request_id"])
            )
            if path in self.router:
                try:
                    response, code = self.router[path](
                        {"body": request, "headers": self.headers},
                        context,
                        self.store
                    )
                except Exception as e:
                    logger.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {
                "error": response or ERRORS.get(code, "Unknown Error"),
                "code": code
            }
        context.update(r)
        logger.info(context)
        self.wfile.write(json.dumps(r).encode())
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logger.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
