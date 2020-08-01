# Performing Ingress and Egress with Bearer Tokens

In this module, you'll create a more secure CORS setup as well as a secure handshake between `Resolutions` and another REST API.

## Verification Steps

Verification is the same as it was for [the last two modules](module_005.md) with one more change.

The repo ships with a simple RESTful service that gives back the user's full name. Of course, we've already added their full name into the app at this point; however, you can imagine the importance of figuring out how to centralize PII and take it out of applications that don't need it all the time.

To start up this RESTful application, do:

```java
./mvnw spring-boot:run -Dstart-class=io.jzheaux.springsecurity.userprofiles.UserProfilesApplication
```

This will start up an application on [http://localhost:8081](http://localhost:8081). It'll be expecting a token from the authorization server, so you'll either need to retrieve one manually or you'll need to connect the goals API to this one (which is what this module is all about).

At the end of this module, when you go to [http://localhost:4000/bearer.html], the front-end will be talking to `Resolutions`, but also `Resolutions` will be talking to another REST API.