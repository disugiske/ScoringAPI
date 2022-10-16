#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import inspect
import json
from datetime import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import BaseHTTPRequestHandler, HTTPServer

from exc import RequiedError, ArgJsonError

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
        self.verify_required(value)
        result = self.verify(value)
        print("result:", result)
        instance.__dict__[self.name] = result

    def verify_required(self, arg):
        if self.required and arg is None:
            print(f'{self.name} field is required!')
            raise ValueError(f'{self.name} field is required!')
        if not self.nullable and not arg.strip("[]{}""''()"):
            print(f'{self.name} is not nullable')
            raise ValueError(f'{self.name} is not nullable')



    # def verify_params(self, arg, instance):
    #     #result = self.verify(arg)
    #     print('3')
    #     #setattr(instance, self.name, result)
    #     return self.verify(arg)


class CharField(Inition):
    def verify(self, arg):
        if type(arg) != str:
            raise TypeError(f"{self.name}:{arg} is not string")
        else:
            return arg


class ArgumentsField(Inition):
    @staticmethod
    def verify(arg):
        try:
            dump = json.dumps(arg)
            json.loads(dump)
            return arg
        except TypeError:
            raise TypeError(f'argument: {arg} is not valid json')


class EmailField(Inition):
    @staticmethod
    def verify(arg):
        if not "@" and "." in arg:
            raise TypeError(f"email: {arg} is not valid email")
        else:
            return arg


class PhoneField(Inition):
    @staticmethod
    def verify(arg):
        print("this")
        arg = str(arg)
        if not arg.isdigit() and len(arg) == 11 and int(arg[:1]) == 7:
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
    ValueError(f"brithday: field is not valid format")

    @staticmethod
    def verify(arg):
        try:
            delta = datetime.now() - datetime.strptime(arg, '%d.%m.%Y')
        except ValueError:
            raise ValueError(f"brithday: field {arg} is not valid format")
        if not delta.days / 365 < 70:
            raise ValueError(f"brithday: age > 70 years")
        else:
            return arg


class GenderField(Inition):
    @staticmethod
    def verify(arg):
        if str(arg).strip("123"):
            raise ValueError("gender: not valid")
        else:
            return arg


class ClientIDsField(Inition):
    @staticmethod
    def verify(arg):
        if arg != list and arg[0] != int:
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
    # __slots__ = "account", "login", "req"
    def __init__(self, req):
        self.req = req
        print(self.req)
        try:
            self.responce = self.init_attrs()
        except ValueError as e:
            self.responce = str(e), 422
        # self.make_request(req)

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
    client_ids = ClientIDsField(required=True, nullable=False)
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
        digest = hashlib.sha512((datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode()).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode()).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    if request["body"] == {}:
        print(ERRORS[422], 422)
        return ERRORS[422], 422
    request_method = MethodRequest(req=request["body"])
    if request_method.responce:
        print(request_method.responce)
        return request_method.responce
    if not check_auth(request_method):
        print(ERRORS[403], FORBIDDEN)
        return ERRORS[403], FORBIDDEN
    if request["body"]["method"] == "online_score":
        if request["body"].get("arguments") is None:
            return ERRORS[422], 422
        check_arguments = OnlineScoreRequest(req=request["body"]["arguments"])
        if check_arguments.responce:
            return check_arguments
    if request["body"]['method'] == "clients_interests":
        print("this")
        clients_interests = ClientsInterestsRequest(req=request["body"])
        if clients_interests.responce:
            return clients_interests.responce
    return "asdasd", OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        print(request)
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
