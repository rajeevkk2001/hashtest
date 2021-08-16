# Broken hash test suite

This is a test suite created for testing the broken has app  using the pytest python module.
This has the implementations for parallel execution of tests and html report generation 


## How to Setup

 1. Clone the Github Repo onto your local machine.
 2. Install the dependencies using the below command:
	> pip Install -r requirements.txt


## What is covered in the tests
There are mainly 2 tests. 
 1. test_suite1.py 
 2. test_suite2.py
 test_suite1.py is designed to execute all tests in parallel and can complete in 30 seconds if we run with 5 threads
 test_suite2.py is designed to run sequentially as there are dependent shutdown related scenarios and can finish in 80 seconds

 #1. test_suite1.py : Covers the following 25 testcases
    test_get_stats_no_body_verify_response_text
    test_check_empty_data_hash	
    test_ping_application_and_getresponse
    test_get_stats_status_code
    test_is_post_hash_supported
    test_check_if_job_identifier_is_returned_for_post_hash
    test_check_response_time_for_job_identifier
    test_verify_get_hash_endpoint_supported	
    test_verify_stats_endpoint_supported
    test_check_post_hash_with_malformed_input
    test_check_totalrequests_key_stats_response
    test_check_whether_key_password_can_be_passed_as_camelcase_letters
    test_check_whether_key_can_be_passed_as_capital_letters
    test_parallel_get_requests_stats
    test_check_averagetime_key_stats_response
    test_gethash_nonexisting_jobidentifier
    test_check_password_is_hashed_using_sha512_base64_encoding
    test_check_empty_string_allowed_as_password
    test_max_length_validation_for_password	
    test_check_post_hash_with_different_key_pass
    test_string_with_special_character_allowed_as_password
    test_whether_stats_endpoint_supports_post
    test_check_whether_stats_endpoint_accept_parameters
    test_check_post_hash_with_different_key
 #2. test_suite2.py : covers the following 5 testcases
    test_is_remaining_password_hashing_allowed_to_complete
    test_simultaneous_post_hash
    test_simultaneous_get_hash
    test_check_if_totalRequest_are_Incrementing
    test_check_successful_shutdown

 
## How to Run The Tests		
    pytest test_suite1.py -s -v --capture=tee-sys --html=testsuite1Report.html -n 5
    pytest test_suite2.py -s -v --capture=tee-sys --html=testsuite2report.html
  
## How to view the reports
    Open testsuite1Report.html andtestsuite2report.html in any desired browser ( preferably chrome)

## What is expected during and after execution
    1.The application of broken has will be open and place the api requests based on the testcase, 
    once the execution is complete it will generate the execution report in a file names testsuite1Report.html and testsuite2report.html .
    2. Open the html in a browser( preferably chrome ) to see the details of the results
    3. All the assertions are done using pytest_check, if any test got failed, details of the failures will be captured in testsuite1Report.html andtestsuite2report.html
    4. At the end of execution the script will also provide a console, which will have more details of the execution if interested
    5. Broken share application is placed in the project directory itself, the port setting and will done through the code itself, 
    no need of setting the port manually in the environment variables
    6. Failed results in the testsuite1Report.html andtestsuite2report.html file are bugs.
    
    
 ## Improvements
     1. As of now I have placed all the tests and other common utils in same diretcoty. This can be more organized way by
     designing it as a framework where in tests, utils, reports, data and business fucntions in separate folders so that the maitainability can be very easy and 
     all the test suite will be in a structured way.
     2. Some of the fucntions need further improvisation, with error handling, and to avoid duplications
 ## Bugs
    1. Post request to hash is accepting empty string as the password. Any application should not take empty string as the password
    2. Invalid password with only special characters is allowing as password. TestData: ABC~!@$%^&&*()_+ 
    3. Password should be the only key allowed in POST request to hash endpoint. But its accepting other keys as well. eg: {"pass": "angrymonkey"} returns 200 OK
    4. Checked whether system is accpeting single character as key in place of password and returned 200 OK. {"p": "angrymonkey"}
    5. Application is accepting empty key in place of the password. eg: {"": "angrymonkey"} Application should  allow a single key, password
    6. Checked whether  the end point stats support post request, eg: http://127.0.0.1:8088/stats  on POST and returned 200 OK. It should allow only GET
    7. Checked that the stats endpoint does not support parameters on GET request eg: http://127.0.0.1:8088/stats?name1=value1&name2=value2  on GET and returned 200 OK. It should not allow parameters
    8. The last one I found was for the requirement "No additional password requests should be allowed when shutdown is pending". I think there is bug in this area, its additional post when shutdown is in pending.    
      
