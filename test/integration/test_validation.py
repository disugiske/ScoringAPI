import functools
import unittest
import api


def cases(cases):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args):
            for c in cases:
                new_args = args + (c if isinstance(c, tuple) else (c,))
                try:
                    f(*new_args)
                except AssertionError:
                    raise AssertionError(f"Error in line {c}")

        return wrapper

    return decorator


class TestOKValidation(unittest.TestCase):

    @cases([
        [2], [1], [0], [2333]
    ])
    def test_ok_client_ids(self, arg):
        self.client_ids = api.ClientIDsField(required=True, nullable=False)
        self.assertEqual(arg, self.client_ids.verify(arg))

    @cases([
        "01.01.2022", "02.03.2020"
    ])
    def test_ok_date(self, arg):
        date = api.DateField(required=False, nullable=True)
        self.assertEqual(arg, date.verify(arg))

    @cases([
        '', 'hey', 'Lorem'
    ])
    def test_ok_charfield(self, arg):
        charfield = api.CharField(required=False, nullable=True)
        self.assertEqual(charfield.verify(arg), arg)

    @cases([
        'test@yandex.ru', '123@yandex.ru'
    ])
    def test_ok_emailfield(self, arg):
        email = api.EmailField(required=False, nullable=True)
        self.assertEqual(arg, email.verify(arg))

    @cases([
        79033332211, '79033332211'
    ])
    def test_ok_phone_field(self, arg):
        phone = api.PhoneField(required=False, nullable=True)
        self.assertTrue(phone.verify(arg))

    @cases([
        '20.11.2017', '20.07.1999'
    ])
    def test_ok_birthday(self, arg):
        birthday = api.BirthDayField(required=False, nullable=True)
        self.assertEqual(arg, birthday.verify(arg))

    @cases([
        2, 1, 0
    ])
    def test_ok_gender(self, arg):
        gender = api.GenderField(required=False, nullable=True)
        self.assertEqual(arg, gender.verify(arg))

    @cases([
        {}, {"hello": "world"}, {"gender": 2, "birthday": "01.01.2000"}
    ])
    def test_ok_arguments(self, arg):
        arguments = api.ArgumentsField(required=True, nullable=True)
        self.assertEqual(arg, arguments.verify(arg))


class TestBadValidation(unittest.TestCase):
    @cases([
        [], [''], ['3'], '', '{}', '[]', 'two', ['one'], [0.5]
    ])
    def test_bad_client_ids(self, arg):
        self.client_ids = api.ClientIDsField(required=True, nullable=False)
        with self.assertRaises(TypeError):
            self.client_ids.verify(arg)

    @cases([
        "2022-11-28 00:08:43", "2022-11-28", "01-01-2022", "01.13.2022", "45.12.2022"
    ])
    def test_bad_date(self, arg):
        date = api.DateField(required=False, nullable=True)
        with self.assertRaises(ValueError):
            date.verify(arg)

    @cases([
        2, 123, ["lorem"], {'test'}, [], {}
    ])
    def test_bad_charfield(self, arg):
        charfield = api.CharField(required=False, nullable=True)
        charfield.name = arg
        with self.assertRaises(TypeError):
            charfield.verify(arg)

    @cases([
        123, [], {}, ['test@yandex.ru'], 'test.test.ru', "test.ru"
    ])
    def test_bad_emailfield(self, arg):
        email = api.EmailField(required=False, nullable=True)
        with self.assertRaises(TypeError):
            email.verify(arg)

    @cases([
        790333322111, '89033332211', '+79034443322', '790322211000', '9032224444'
    ])
    def test_bad_phone_field(self, arg):
        phone = api.PhoneField(required=False, nullable=True)
        with self.assertRaises(TypeError):
            phone.verify(arg)

    @cases([
        '20.13.2017', '20.07.1910', '33.11.2012', '20-13-2017'
    ])
    def test_bad_birthday(self, arg):
        birthday = api.BirthDayField(required=False, nullable=True)
        with self.assertRaises(ValueError):
            birthday.verify(arg)

    @cases([
        '4', 4, -1, -3, 0.5, '0.5', '0'
    ])
    def test_bad_gender(self, arg):
        gender = api.GenderField(required=False, nullable=True)
        with self.assertRaises(ValueError):
            gender.verify(arg)

    @cases([
        0, [], "test", "{}"
    ])
    def test_bad_arguments(self, arg):
        arguments = api.ArgumentsField(required=True, nullable=True)
        with self.assertRaises(TypeError):
            arguments.verify(arg)


if __name__ == "__main__":
    unittest.main()
