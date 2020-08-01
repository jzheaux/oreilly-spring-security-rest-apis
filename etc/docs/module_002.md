# Authorizing Requests with HTTP Basic

In this module, you'll add method-based authorization rules to your REST API.

## CSRF

Note that by default, Spring Security leaves CSRF turned on. 
For the first 2-3 modules, this will mean that the `POST` and `PUT` endpoints in this API will return a `403`.

You can lift this restriction if you'd like to play around with these endpoints; look for details in Step 9 of this module to see a simple way to do this. 

## Verification Steps

Once you've configured Spring Security with a username and password, you can work with the API like any other REST API.

You can use your favorite HTTP client, like [Postman](https://getpostman.com), cURL, or [HTTPie](https://httpie.org). The following instructions will use HTTPie.

In all the instructions, `$USER` is the username, and `$PASS` is the password.

### Get a List of Resolutions
```bash
http -a $USER:$PASS :8080/goals
```
### Lookup a Resolution by Id
```bash
http -a $USER:$PASS :8080/goal/$ID
```
where `$ID` is the primary key.
### Create a Resolution
```bash
echo -n "some text" | http -a $USER:$PASS :8080/goal
```
### Revise a Resolution
```bash
echo -n "some updated text" | http -a $USER:$PASS PUT :8080/goal/$ID/revise
```
### Complete a Resolution
```bash
http -a $USER:$PASS PUT :8080/goal/$ID/complete
```