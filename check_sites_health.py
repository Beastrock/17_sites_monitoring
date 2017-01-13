import whois
import datetime
import argparse
import os.path
from requests import get
from requests import exceptions
from urllib.parse import urlparse


def get_args():
    parser = argparse.ArgumentParser(description="Site monitoring utility")
    parser.add_argument("-f", dest="filepath",
                        help="filepath to urls txt file", type=str, required=True)
    return parser.parse_args()


def load_urls_list_from_file(filepath):
    if not os.path.exists(filepath):
        return None
    with open(filepath, "r", encoding="utf-8") as file_handler:
        return file_handler.read().split()


def is_server_respond_with_200(url):
    try:
        return get(url, timeout=10).status_code == 200
    except exceptions.ConnectionError:
        return None


def is_expiration_date_paid_status(url, min_days_left_to_expiration_date=30):
    try:
        expiration_date_responce = whois.whois(urlparse(url).netloc).expiration_date
    except whois.parser.PywhoisError:
        expiration_date_responce = None
    if isinstance(expiration_date_responce, datetime.datetime):
        expiration_date = expiration_date_responce.date()
    elif isinstance(expiration_date_responce, list):
        expiration_date = expiration_date_responce[0].date()
    else:
        return None
    todays_date = datetime.datetime.now().date()
    days_till_domain_expiration = (expiration_date - todays_date).days
    return days_till_domain_expiration > min_days_left_to_expiration_date


def get_urls_sites_statistic(urls):
    expiration_date_statistic = ["PASSED" if is_expiration_date_paid_status(url)
                                 else "FAILED" for url in urls]
    server_respond_statistic = ["PASSED" if is_server_respond_with_200(url)
                                else "FAILED" for url in urls]
    return [(urlparse(url).netloc, expiration_date_status, server_respond_status)
            for url, expiration_date_status, server_respond_status
            in zip(urls, expiration_date_statistic, server_respond_statistic)]


def output_statistic_to_the_console(statistic):
    print("|{:^21}|{:^22}|{:^25}|".
          format("SERVER RESPOND STATUS", "EXPIRATION DATE STATUS", "DOMAIN"))
    for domain, expiration_status, server_respond_status in statistic:
        print("|{:^21}|{:^22}| {:24}|".
              format(server_respond_status, expiration_status, domain))


if __name__ == "__main__":
    args = get_args()
    urls = load_urls_list_from_file(args.filepath)
    statistics = get_urls_sites_statistic(urls)
    output_statistic_to_the_console(statistics)
