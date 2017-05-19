# pwbridge: a client/server approach to the pwd module

`pwbridge` lets your Python application talk to a service that responds
queries for UNIX user names with the UID, GID, full name and groups of
the user names in question.

It is useful when your Docker container needs to get the host's UID and GID
of particular users on your host.

## License

This program is distributed under the [Apache 2.0](LICENSE) license.

