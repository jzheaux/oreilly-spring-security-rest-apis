# Using CORS and HTTP Basic

In this module, you'll configure the REST API to perform a CORS handshake so that it can be used by clients from a different hostname.

## Verification Steps

To start up the front-end application, run from the root of the project:

```bash
./mvnw spring-boot:run -Dstart-class=io.jzheaux.springsecurity.spa.SpaApplication
```

At that point, a very simple single-page application will be available at [http://localhost:4000/basic.html](http://localhost:4000/basic.html). 
You'll be asked to log in.
To get the goals to show, click the `Goals` button.

In the beginning, the app will fail, but worry not! In this module, you'll make the CORS handshake succeed.

## Extra Credit

Note that the reason this app still works even with CSRF enabled is because this application is only performing a `GET`.

Were it also doing writes (`POST`, `PUT`, or `DELETE`), you'd need to configure CSRF to write the CSRF token as a cookie and then return it with each request.