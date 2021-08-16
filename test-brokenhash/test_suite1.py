import base64
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor as PoolExecutor
import pytest
import requests
import pytest_check as check
from app_manager import App
from common import password, baseUrl

app = App()

def test_check_empty_data_hash():
    """
    Test to check that empty JSON cannot be passed in POST request to hash endpoint
    Arguments:
    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count, " Test to check that empty JSON cannot be passed in POST request to hash endpoint")
    psw = {}
    res = app.post_hash(psw)
    print("Data used is ", json.dumps(psw))
    test_status = check.is_not_in(str(res.status_code), '200',
                                  "Empty JSON is accepting in POST request to hash endpoint")
    print("Response displayed is :", res.text, "Status code is :", res.status_code)
    if test_status:
        print("PASS: Verified that empty JSON cannot be passed in POST request to hash endpoint")
    else:
        print("FAIL: Empty JSON should not be allowed to be passed to the hash endpoint")


def test_get_stats_status_code():
    """
        Test to verify the status code for get request for the endpoint "/stats"
        Arguments:
        Return Values:
        """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count, "- Test to verify the status code for stats endpoint")
    statuscode = app.get_stats_statuscode()
    print("Status code is " + str(statuscode))
    test_status = check.equal(str(statuscode), '200', "Empty JSON is accepting in POST request to hash endpoint")
    if test_status:
        print("PASS: Verified that status code for stats endpoint returns 200")
    else:
        print("stats endpoint status code verification failed")


def test_ping_application_and_getresponse():
    """
        This test is to ping the application and get response
        Arguments:
        Return Values:
        """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count, "- This test is to ping the application and get response")
    res = app.pingHost()
    test_status = check.is_true(res)
    if test_status:
        print("PASS: Verified that ping command is success and received the response")
    else:
        print("FAIL: Failed to verify the application ping")


def test_is_post_hash_supported():
    """
         This  is to test the application support /hash endpoint
         Arguments: password
         Return Values: response(obj)
         """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count, " - This  is to test the application support /hash endpoint")
    res = app.post_hash(password)
    test_status = check.equal(str(res.status_code), '200', "Application is not supporting hash endpoint")
    print("Status code received is ", str(res.status_code))
    if test_status:
        print("Verified that the application supported hash endpoint")
    else:
        print("Application is not supporting hash endpoint")


def test_get_stats_no_body_verify_response_text():
    """
         This test is verify the response when no body  is send in the request
         Arguments:
         Return Values: response body
         """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count, "This test is verify the response when no body  is send in the request")
    response = app.get_stats_response_text()
    print("Response Received is " + str(response))
    test_status = check.is_true(response)
    if test_status:
        print("PASS: Verified that response is displayed when no body is send in for stats end point")
    else:
        print("FAIL: Response is not displayed when no body is send in for stats end point")


def test_verify_get_hash_endpoint_supported():
    """
    Test to check that GET request to hash endpoint is supported
    Arguments:
        password (str): Password to be hashed and encoded.

    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count, "Test to check that GET request to hash endpoint is supported")
    post_res = app.post_hash(password)
    get_res = app.get_hash(post_res.text)
    test_status = check.equal(str(get_res.status_code), '200', "Failure in GET request to hash endpoint")
    print("Status Code Received is ", str(get_res.status_code))
    if test_status:
        print("PASS: Verified that GET request to hash endpoint is supported")
    else:
        print("FAIL: Failure in GET request to hash endpoint")


def test_check_if_job_identifier_is_returned_for_post_hash():
    """
    Test to check that job identifier is returned when submitting POST request to hash endpoint

    Arguments:
        password (str): Password to be hashed and encoded.

    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check that job identifier is returned when submitting POST request to hash endpoint")
    res = app.post_hash(password)
    test_status = check.equal(str(res.status_code), '200', "Job identifier is not returned")
    print("Status Code Received is " + str(res.status_code))
    if test_status:
        print("PASS: Verified that job identifier ", res.text,
              " is returned when submitting POST request to hash endpoint")
    else:
        print("FAIL: Job identifier is not returned")
        print("No job identifier was returned")


def test_check_response_time_for_job_identifier():
    """
    Test to check that job identifier is returned immediately when submitting POST request to hash endpoint
    Arguments:
        password (str): Password to be hashed and encoded.
    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check that job identifier is returned immediately when submitting POST request to hash endpoint")
    start_time = time.time()
    print("Start time is: ", str(start_time))
    res = app.post_hash(password)
    end_time = time.time() - start_time
    print("Response Time is: ", str(end_time))
    print(round(end_time))
    test_status = check.is_true(round(end_time) <= 5)
    if test_status:
        print("PASS: Job identifier expected to return in less than", round(end_time), "seconds")
    else:
        pytest.fail("FAIL: Job identifier not returned immediately")
        print("FAIL: Job identifier not returned immediately")
        print("Job identifier took ", str(end_time), " seconds to return")
        print("Job identifier expected to return in  5 seconds")


def test_verify_stats_endpoint_supported():
    """
    Test to check that GET request to stats endpoint is supported
    Arguments:
    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count, "Test to check that GET request to stats endpoint is supported")
    endpoint = '/stats'
    res = requests.get(baseUrl + endpoint)
    test_status = check.equal(str(res.status_code), '200', "Failure when placing GET request t stats endpoint")
    print("Status code received is ", str(res.status_code))
    print("Response received is ", res.text)
    if test_status:
        print("PASS: Verified that GET request to stats endpoint is supported")
    else:
        print("FAIL: Failure while placing GET request to stats endpoint")


def test_check_empty_string_allowed_as_password():
    """
    Test to check that an empty string cannot be passed as a password

    Arguments:
        password (str): Password to be hashed and encoded.

    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count, "Test to check that an empty string cannot be passed as a password")
    psw = ""
    res = app.post_hash(psw)
    test_status = check.not_equal(str(res.status_code), '200', "Failure:empty string as password ")
    print("Password tried is :", psw)
    print("Status Code received is ", str(res.status_code))
    if test_status:
        print("PASS: Verified that empty string cannot be passed as a password")
    else:
        print("FAIL: Empty string should not be allowed as a password")


def test_string_with_special_character_allowed_as_password():
    """
    Test to check that Invalid password with special characters as a password

    Arguments:
        password (str): Password to be hashed and encoded.

    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count, "Test to check that Invalid password with special characters as a password")
    password = "ABC~!@$%^&&*()_+"
    res = app.post_hash(password)
    test_status = check.not_equal(str(res.status_code), '200',
                                  "Failure:Invalid password with special characters is accepting as password ")
    print("Password tried is :", password)
    print("Status Code Received is ", str(res.status_code))
    if test_status:
        print("PASS: Verified that Invalid password with special characters cannot be passed as a password")
    else:
        print("FAIL: Invalid password with special characters is accepting as password")


def test_max_length_validation_for_password():
    """
    Test to check whether there is maximum length defined for the password

    Arguments:
        password (str): Password to be hashed and encoded.

    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count, "Test to check whether there is maximum length denfined for the password")
    password = "asdasd~!@#@!#%^&@#^*$&@$*@(*)$!((()___*)_^&^*ASDFSDGDGKDFGKDFGKFDXM,CVBVNdvnmxcmvb skdfjhsfhsjkfskfjskfsk" \
               "dfgkdkfgdl;fgjdflkgjdlfgkdlfgkjdlfkgjldkfjgdlkfjgldfkgjeroiutgkjdflkgjdflgkjdf;gjdfgdfgdkfgkldjfgldfjdlfgjl"
    res = app.post_hash(password)
    test_status = check.not_equal(str(res.status_code), '200', "Failure:No max length defined for the password ")
    print("Password tried is :", password)
    print("Status Code Received is ", str(res.status_code))
    if test_status:
        print("PASS: Verified that maximum length is defined for the password")
    else:
        print("FAIL: No max length defined for the password")


def test_check_post_hash_with_malformed_input():
    """
    Test to check that malformed JSON cannot be passed in the POST request to hash endpoint
    Arguments:
    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check that malformed JSON cannot be passed in the POST request to hash endpoint")
    endpoint = '/hash'
    params = '{"password": "password", }'
    res = requests.post(baseUrl + endpoint, json=password)
    test_status = check.not_equal(str(res.status_code), '200',
                                  "Failure:malformed JSON is accepting in the POST request to hash endpoin ")
    print("Data used is: ", json.dumps(params))
    print("Status code received is: ", str(res.status_code))
    if test_status:
        print("PASS: Verified that malformed JSON cannot be passed in the POST request to hash endpoint")
    else:
        print("FAIL: Malformed JSON should not be allowed in POST request to hash endpoint")


def test_check_post_hash_with_different_key():
    """
    Test to check that a key other than password cannot be passed in POST request to hash endpoint
    Arguments:
        password (str): Password to be hashed and encoded.
    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check that a key other than password cannot be passed in POST request to hash endpoint")
    endpoint = '/hash'
    params = {
        'p': password
    }

    res = requests.post(baseUrl + endpoint, json=params)
    test_status = check.not_equal(str(res.status_code), '200',
                                  "key other than password accepting in POST request to hash endpoint")
    print("Data used is: ", json.dumps(params))
    print("Status code received is: ", str(res.status_code))
    if test_status:
        print("PASS: Verified that a key other than password cannot be passed in POST request to hash endpoint")
    else:
        print("FAIL: password should be the only key allowed in POST request to hash endpoint")


def test_check_post_hash_with_different_key_pass():
    """
    Test to check that a key other than password cannot be passed in POST request to hash endpoint
    Arguments:
        pass (str): Password to be hashed and encoded.
    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check that a key other than password cannot be passed in POST request to hash endpoint")
    endpoint = '/hash'
    params = {
        'pass': password
    }
    res = requests.post(baseUrl + endpoint, json=params)
    test_status = check.not_equal(str(res.status_code), '200', "key pass in accepting in place of password")
    print("Data used is: " + json.dumps(params))
    print("Status code received is: ", str(res.status_code))
    if test_status:
        print("PASS: Verified that a key other than password cannot be passed in POST request to hash endpoint")
    else:
        print("FAIL: password should be the only key allowed in POST request to hash endpoint")


def test_check_whether_key_can_be_passed_as_capital_letters():
    """
    Test to check that a key passed in not case sensitive
    Arguments:
        pass (str): Password to be hashed and encoded.
    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check that a key passed in not case sensitive")
    endpoint = '/hash'
    params = {
        'PASSWORD': password
    }

    res = requests.post(baseUrl + endpoint, json=params)
    test_status = check.equal(str(res.status_code), '200', "key PASSWORD in accepting in place of password")
    print("Data used is: " + json.dumps(params))
    print("Status code received is: ", str(res.status_code))
    if test_status:
        print("PASS: Verified that that a key passed in UPPER CASE LETTERS in POST request to hash endpoint")
    else:
        print("FAIL : Failure when key passed in UPPER CASE LETTERS in POST request to hash endpoint")


def test_check_whether_key_password_can_be_passed_as_camelcase_letters():
    """
    Test to check that a key passed in camelcase
    Arguments:
        pass (str): Password to be hashed and encoded.
    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check that a key passed in camelcase")
    endpoint = '/hash'
    params = {
        'PassWord': password
    }

    res = requests.post(baseUrl + endpoint, json=params)
    test_status = check.equal(str(res.status_code), '200', "key PassWord in accepting in place of password")
    print("Data used is: " + json.dumps(params))
    print("Status code received is: ", str(res.status_code))
    if test_status:
        print("PASS: Verified that that a key passed in Camel case letter in POST request to hash endpoint")
    else:
        print("FAIL : Failure when key passed in Camel case letter in POST in POST request to hash endpoint")
def test_check_response_with_empty_key_in_place_of_password():
    """
    Test to check the response with empty key in place of password
    Arguments:
        empty (str): Password to be hashed and encoded.
    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check the response with empty key in place of password")
    endpoint = '/hash'
    params = {
        '': password
    }

    res = requests.post(baseUrl + endpoint, json=params)
    test_status = check.not_equal(str(res.status_code), '200', "empty key  in accepting in place of password")
    print("Data used is: " + json.dumps(params))
    print("Status code received is: ", str(res.status_code))
    if not test_status:
        print("PASS: Verified that that empty key cannot be passed in POST request to hash endpoint")
    else:
        print("FAIL : empty key is accepting in place of password in POST request to hash endpoint")


def test_check_totalrequests_key_stats_response():
    """
    Test to check that TotalRequests is a Key in JSON Response from stats endpoint
    Arguments:
    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check that TotalRequests is a Key in JSON Response from stats endpoint")

    key = 'TotalRequests'
    endpoint = '/stats'
    res = requests.get(baseUrl + endpoint)
    key_exists = app.is_key(json.dumps(res.json()), key)
    test_status = check.is_true(key_exists)
    print("Response received is: ", res.text)
    print("Status Code received is: ", str(res.status_code))
    if test_status:
        print("PASS: Verified that TotalRequests is a Key in JSON Response from stats endpoint")
    else:
        print("FAIL: TotalRequests is not a Key in JSON Response from stats endpoint")


def test_check_averagetime_key_stats_response():
    """
    Test to check that AverageTime tag is key in JSON Response for stats endpoint
    Arguments:
    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check that AverageTime tag is key in JSON Response for stats endpoint")
    key = 'AverageTime'
    endpoint = '/stats'
    res = requests.get(baseUrl + endpoint)
    key_exists = app.is_key(json.dumps(res.json()), key)
    test_status = check.is_true(key_exists)
    print("Response received is: ", res.text)
    print("Status Code received is: ", str(res.status_code))
    if test_status:
        print("PASS: Verified that AverageTime tag is key in JSON Response for stats endpoint")
    else:
        print("FAIL: Verified that AverageTime tag is Not a  key in JSON Response for stats endpoint")


def test_whether_stats_endpoint_supports_post():
    """
    Test to check that whether stats endpoint support POST
    Arguments:
    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check that whether stats endpoint support POST")
    endpoint = '/stats'
    request = baseUrl + endpoint
    print("Request is : ", request, " on POST")
    res = requests.post(baseUrl + endpoint)
    print("Response received is: ", res.text)
    print("Status Code received is: ", res.status_code)
    test_status = check.not_equal(str(res.status_code), '200', "FAIL:stats endpoint support POST request")

    if test_status:
        print("PASS:Verified that stats endpoint does not support POST request")
    else:
        print("FAIL: stats endpoint is supporting POST request")
        print("The stats endpoint should not support POST request")


def test_check_whether_stats_endpoint_accept_parameters():
    """
    Test to check that the stats endpoint does not support parameters on GET request
    Arguments:
    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check that the stats endpoint does not support parameters on GET request")
    endpoint = '/stats'
    params = '?name1=value1&name2=value2'
    request = baseUrl + endpoint + params
    res = requests.get(request)
    print("Request is ", str(request), " on GET")
    test_status = check.not_equal(str(res.status_code), '200', "FAIL:stats endpoint support parameters on GET request")
    print("Response received is: ", str(res.text))
    print("Status Code received is: ", str(res.status_code))
    if test_status:
        print("PASS:Verified that stats endpoint does not support parameters in request")
    else:
        print("FAIL: stats endpoint is supporting parameters in GET request")
        print("The stats endpoint should not support parameters in GET request")



def test_check_password_is_hashed_using_sha512_and_base64_encoding():
    """
    Test to check that password is hashed using SHA512 hashing algorithm and base64 encoded.

    Arguments:
        password (str): Password to be hashed and encoded.

    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check that password is hashed using SHA512 hashing algorithm and base64 encoded.")

    print("Password to be encoded is ",password)
    post_res = app.post_hash(password)
    print("Job identifier returned is ",post_res.text)
    get_res = app.get_hash(post_res.text)
    print("Get the encoded password for job id  ",get_res.text," from the applications is ", post_res.text)

    expected_encode = base64.b64encode(hashlib.sha512(str.encode(password)).digest())
    print("Encoded value returned from using SHA512 algorithm and base64 encoded value for password ",password," is",expected_encode)
    test_status = check.is_in(str(get_res.text),str(expected_encode),"Failure in hash using SHA512 hashing algorithm and base64 encoding")
    if  test_status :
        print("PASS: Verified that password is hashed using SHA512 hashing algorithm and base64 encoding")
    else:
        print("FAIL: test_is_password_encoded")
        print("Expected Encoded Value: ") + expected_encode
        print("Actual Encoded Value from the application: ") + get_res.text


def test_gethash_nonexisting_jobidentifier():
    """
    Test to check that GET request hash endpoint with a non existent job identifier is not supported.
    Arguments:
    Returns:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check that GET request hash endpoint with a non existent job identifier is not supported.")
    jobid = '99999'
    res = app.get_hash(jobid)
    print("Response received is ", res.text)
    test_status = check.is_in('Hash not found', res.text,
                              "Failure: when placing GET request with non existing job identifier")
    if test_status:
        print(
            "PASS: Verified that Has not found message is displayed when placing request with nonexisting job identifier ",
            jobid)
    else:
        print("FAIL: The hash endpoint should not support GET request with non existent job identifier ", json)


def get_it(url):
    try:
        data = {'password': password}
        headers = {'Accept': 'application/json'}
        endPoint = "/hash"
        response = requests.post(baseUrl + endPoint, json=data, headers=headers).json()
        return response
    except requests.exceptions.RequestException as e:
        print(e)
        pass


def test_parallel_get_requests_stats():
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to whether parallel requests are supported by the application")
    endpoint = "/stats"
    urls = [
               baseUrl + endpoint,
               baseUrl + endpoint,
               baseUrl + endpoint,
               baseUrl + endpoint
           ] * 3
    with PoolExecutor(max_workers=4) as executor:
        for resp in executor.map(get_it, urls):
            print(resp)
