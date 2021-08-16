import multiprocessing as mp
from multiprocessing import Process, Queue

import pytest
import requests
from app_manager import App
from common import passwords, baseUrl, password
import pytest_check as check

app = App()
testcas_count = 0


def post_hash(multiprocessQueue=None):
    """
    Function to submit POST request to hash endpoint.

    Arguments:
        password (str): Password to be hashed and encoded.
        multiprocessQueue (obj): Multiprocessing multiprocessQueue object to hold response object

    Return Values:
        res (obj): Response object from POST request
    """

    endpoint = '/hash'
    params = {
        'password': password
    }
    res = app.req.post(baseUrl + endpoint, json=params)

    if multiprocessQueue is not None:
        multiprocessQueue.put(res)
    else:
        return res


def shutdown(multiprocessqueue=None):
    """
    Function to initiate shutdown request to hash endpoint.

    Arguments:
        multiprocessQueue (obj): Multiprocessing multiprocessQueue object to hold response object

    Return Values:
        res (obj): Response object from POST request
    """

    endpoint = '/hash'
    data = 'shutdown'

    res = app.req.post(baseUrl + endpoint, data=data)
    if multiprocessqueue is not None:
        multiprocessqueue.put(res)
    else:
        return res


def test_is_remaining_password_hashing_allowed_to_complete():
    """
    Test to check application support a graceful shutdown request. Meaning, it should allow any in-flight password hashing to complete.

    Arguments:
        passwords (str): Password to be hashed and encoded.
    Return Values:
    """
    testcas_count = + 1
    print("Testcase :", str(testcas_count),
          " - Test to check application support a graceful shutdown request. Meaning, it should allow any in-flight password hashing to complete.")
    queue = Queue()
    p1 = Process(target=shutdown, args=(queue,))
    p1.start()
    print("Starting process for Shutdown...")
    p2 = Process(target=post_hash, args=(queue,))

    shutdown_res = queue.get()
    p2.start()
    print("Starting process for password hash in parallel...")

    if shutdown_res.status_code >= 300 or shutdown_res.status_code < 200 or shutdown_res.text:
        pytest.fail("FAIL: Shutdown did not succeed or shutdown response did not come first")
        print("FAIL: Shutdown did not succeed or shutdown response did not come first")
        print("Shutdown Response: ", shutdown_res.text)
    else:
        post_res = queue.get()
        if (post_res.status_code >= 300 or post_res.status_code < 200 or not post_res.text):
            pytest.fail("FAIL: POST to Hash did not succeed or response was empty")
            print("FAIL: POST to Hash did not succeed or response was empty")
            print("POST Response: ", post_res.text)
        else:
            print("Status code for shutdown request is ", shutdown_res.status_code)
            print("Status code for inflight password hash request is ", shutdown_res.status_code)
            print(
                "PASS: Verified that the application supported graceful shutdown request,allow any in-flight password hashing to complete")


def test_simultaneous_post_hash():
    """
    Test to check that simultaneous POST requests are supported by hash endpoint.

    Args:
        passwords (str list): Passwords to be hashed and encoded.

    Returns:
    """
    testcas_count = + 1
    print("Testcase :", str(testcas_count),
          " - This test is to check that simultaneous POST requests are supported for hash endpoint")
    success = True
    processes = mp.Pool(mp.cpu_count())
    hash_ids = []
    print("Place simultaneous post request with passwords ", passwords)
    responses = processes.map_async(app.post_hash, passwords).get(999999)
    for res in responses:
        hash_ids.append(res.text)
        if (res.status_code != 200):
            success = False
            break

    if check.is_true(success):
        print("PASS: Verified that simultaneous POST requests are supported for /hash endpoint.")
    else:
        print("FAIL: simultaneous POST requests were not supported for /hash endpoint")
    processes.close()
    processes.join()
    print("Job Identifiers response received for post requests--> ", hash_ids)


def test_simultaneous_get_hash():
    """
    Test to check that simultaneous GET requests are supported by hash endpoint.
    Args:
        passwords (str list): Passwords to be hashed and encoded.
    Returns:
    """
    app.testcaseCount = + 1
    print("Testcase :", str(app.testcaseCount),
          " - This test is to check that simultaneous GET requests are supported for hash endpoint.")
    hash_ids = []
    res_hashids = []
    for pwd in passwords:
        post_res = app.post_hash(pwd)
        hash_ids.append(post_res.text)
    print(" Placed simultaneous multiple post requests for /hash end point and received hash_ids")
    success = True
    processes = mp.Pool(mp.cpu_count())
    print("Place simultaneous GET  request with list of job identifiers ", hash_ids)
    responses = processes.map_async(app.get_hash, hash_ids).get(999999)

    for res in responses:
        res_hashids.append(res.text)
        if res.status_code != 200:
            success = False
            break

    if check.is_true(success):
        print("PASS: Verified that simultaneous GET requests are supported for hash endpoint.")
    else:
        pytest.fail("FAIL: Failure in simultaneous GET requests on hash endpoint")
        print("FAIL: Failure in simultaneous GET requests on hash endpoint")
    processes.close()
    processes.join()
    print("Encoded passwords are -->", res_hashids)


def test_check_if_total_request_are_incrementing():
    """
    Test to check that TotalRequests are increasing  on subsequent requests
    Arguments:
        password (str): Password to be hashed and encoded.
    Return Values:
    """
    app.open_application()
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "Test to check that TotalRequests are increasing  on subsequent requests")
    endpoint = '/stats'
    request = baseUrl + endpoint
    print("First Request is ", request)
    res = requests.get(baseUrl + endpoint)
    data = res.json()
    print("Response after first Request", res.text)
    expected_requests = data['TotalRequests'] + 1
    print("Number of requests after first request is ", str(data['TotalRequests']))

    res = app.post_hash(password)
    print("Placed a post request on hash. Job identifier returned is ", res.text)
    endpoint = '/stats'
    print("Second request to stats endpoint after post request to hash endpoint is ", request)

    res = requests.get(baseUrl + endpoint)
    data = res.json()
    print("Response for stats end point after post request to has is ", res.text)
    current_requests = data['TotalRequests']
    print("Number of requests after second request is ", str(current_requests))
    test_status = check.equal(str(current_requests), str(expected_requests))
    if test_status:

        print("PASS: Verified that TotalRequests is incremented after second request")
    else:
        print("FAIL: Failure in verifying TotalRequests are incrementing  on subsequent requests")
        print("Expected Value: ", str(expected_requests), "Actual Value: ", str(current_requests))


def test_check_successful_shutdown():
    """
    This test is to check successful shutdown
    Arguments:
    Return Values:
    """
    app.tc_count = app.tc_count + 1
    print("Testcase", app.tc_count,
          "This test is to check successful shutdown")
    res = shutdown()
    test_status = check.equal(str(res.status_code), '200', 'Failure in successful shutdown')
    print("Status Code displayed is : " + str(res.status_code))
    if test_status:
        print("PASS: Verified the successful shutdown")
    else:
        print("FAIL: Failure in verifying successful shutdown")
