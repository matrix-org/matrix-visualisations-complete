# Matrix Visualisations backend

This backend allows
[Matrix Visualisations](https://github.com/Kagamihime/matrix-visualisations)
to directly communicate with the PostgreSQL database of [Synapse](https://github.com/matrix-org/synapse).

## Warning

This is a prototype and there is no authentication system to prevent anyone
from retrieving any events from the database linked to it.
So please **do not** use this with an homeserver in production.

## HTTP REST API

### Get every of the deepest (i.e. with the maximum `depth`) events of a room.

* HTTP request path: `/visualisations/deepest/{roomId}`
* Query parameters: nothing.
* Response format: a JSON object with a field `events` containing the array of
  the JSON bodies of the events.

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
