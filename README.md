# Pwned Check

This library/self-hosted API makes it easy to check if a password is known to be leaked and available publicly.

## How does it work?

Troy Hunt has kindly decided to [share][passwords] his database of pwned passwords with the world.

People are already using his [API][password api] and his more recent [password range API][password range api].

This repository was designed for people who like this but would prefer to keep the data in-house and don't want 30GiB (the current size of the password file) of password hashes in memory.

This library/docker image is a bloom filter for password hashes. Simply sha1 them and receive a response indicating a hit (pwned) or a miss (probably safe).

## Getting started

There is a [docker image][docker image] at 2.1GiB complete with password data on the docker hub.

Alternatively feel free to download the source and build yourself.

To use the library only, just use the normal Go tools:

```go get -u github.com/pedrosland/pwned-check```

## APIs

There are 3 API endpoints provided by pwned-serve. These are all optional if you choose to use the library or you can write your own.

`/pwnedhash/<sha1 hash>` - checks if a SHA1 hash exists in the filter. The main responses are:

```{"in_list": "probably"}```

or:

```{"in_list": "no"}```

`/pwnedpassword/` - provides a nearly compatible endpoint for the deprecated [Have I Been Pwned Password API][password api]. It currently only supports hashes.

`/healthz` - health check endpoint.

## Contributing

Contributions are very welcome. We use Shippable to build our images.

## License

All code is released under the 2-clause BSD license.

[passwords]: https://haveibeenpwned.com/Passwords
[password api]: https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByPassword
[password range api]: https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange

[docker image]: https://hub.docker.com/r/pedrosland/pwned-check/