import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check a password")
    return res


def get_pass_leaks_count(hash_list, hash_to_check):
    hashes = (line.split(':') for line in hash_list.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count

    return 0


def pwned_api_check(password):
    sha1passsword = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_char, tail = sha1passsword[:5], sha1passsword[5:]
    response = request_api_data(first_char)
    # response2 = request_api_data(tail)
    # print(response, response2)
    return get_pass_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"password was found {count}, you should change your password")
        else:
            print(f"password was not found!")

    return 'done'


if __name__=='__main__':
    sys.exit(main(sys.argv[1:]))
