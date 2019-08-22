# Matrix Visualisations backend

This backend allows
[Matrix Visualisations](https://github.com/Kagamihime/matrix-visualisations)
to directly communicate with the PostgreSQL database of
[Synapse](https://github.com/matrix-org/synapse) (in the "postgres mode").
It also allows the usage of the
[Federation API](https://matrix.org/docs/spec/server_server/r0.1.3)
for retrieving events (in the "federation mode").

## Warning

This is a prototype and there is no authentication system to prevent anyone
from retrieving any events from the database linked to it.
So please **do not** use this with an homeserver in production.

## Usage

In order to use the backend in the "postgres mode", you need to run it with:
```
cargo run --release postgres <db_addr> <db_username> <db_name>
```

* `<db_addr>` is the address of the host of the database.
* `<db_username>` is the username to be used when logging in the database.
* `<db_name>` is the name of the database.

In order to use the backend in the "federation mode", you need to run it with:
```
cargo run --release federation <target_addr> <target_name> <server_name> <username>
```

* `<target_addr>` is the address of the HS to observe.
* `<target_name>` is the name of the HS to observe (this can sometimes be different from the address).
* `<server_name>` is the name of the virtual HS created by the backend.
* `<username>` is the name of the virtual user created by the backend.

You will need to create a TLS certificate for "localhost" which will
be stored in the files `cert.pem` and `key.pem`.
You will also need to "steal" the signing keys of a HS. The backend will do
as if it is this HS, so you'll need to pass this server's name as
`<server_name>` and have a file `<server_name>.signing.key`.

## HTTP REST API

### Get every of the deepest (i.e. with the maximum `depth`) events of a room.

* HTTP request path: `/visualisations/deepest/{roomId}`
* Query parameters: nothing.
* Response format: a JSON object with a field `events` containing the array of
  the JSON bodies of the events.

Note: in "federation mode", the backend will create a virtual user and send the event describing the membership change.

### Get ancestors of a set of events.

* HTTP request path: `/visualisations/ancestors/{roomId}`
* Query parameters:
    * `from`: a comma separated list of the IDs of the events from which to
      get the ancestors
    * `limit`: the maximum number of events to return
* Response format: a JSON object with a field “events” containing the array of the
  JSON bodies of the events. Or an error 404 if the room does not exist.

### Get descendants of a set of events.

* HTTP request path: `/visualisations/descendants/{roomId}`
* Query parameters:
    * `from`: a comma separated list of the IDs of the events from which to
    get the ancestors
    * `limit`: the maximum number of events to return
* Response format: a JSON object with a field “events” containing the array of the
  JSON bodies of the events. Or an error 404 if the room does not exist.

### Stop the activity of the backend.

In "federation mode", you will need to tell the backend to delete the virtual
user created for the observation. In "postgres mode", this endpoint will do
nothing except answering with an HTTP OK response.

* HTTP request path: `/visualisations/stop/{roomId}`
* Query parameters: nothing.
* Response format: an HTTP OK response if the backend successfully left the
  room.
