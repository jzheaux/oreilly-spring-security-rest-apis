# Authenticating and Authorizing with JWTs

In this module, you'll add JWT-based Bearer Token Authentication as a more secure alternative to HTTP Basic.

## Verification Steps

Bearer tokens are different from HTTP Basic in that an application relies on a third-party service to authenticate.

The repository ships with a `docker-compose` setup of [Keycloak](https://www.keycloak.org) to achieve this.

To use it, first install and setup [Docker](https://docs.docker.com/get-docker/) and [`docker-compose`](https://docs.docker.com/compose/install).

Then, from the `etc` directory in the repo, do:

```bash
docker-compose up -d
```

This will start a Keycloak server at port 9999 that has `user`, `hasread`, and `haswrite` users, all with password `password`.

You can navigate to [http://localhost:9999](http://localhost:9999) and log in with `admin`/`password` to see the admin console.

Also, you can use the same SPA we used last time. Start it up like before with:

```bash
./mvnw spring-boot:run -Dstart-class=io.jzheaux.springsecurity.spa.SpaApplication
```

And then navigate to [http://localhost:4000/bearer.html](http://localhost:4000/bearer.html). 
The app will negotiate with Keycloak to get you logged in. 
You can use the `Resolutions` button like before.

## Extra Credit

CSRF is automatically disabled for Bearer Token authentication since the browser doesn't automatically store and send those credentials.