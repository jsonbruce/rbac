# RBAC

This project contains a practical RBAC implementation by Golang. It's actually a demo now.
With in-memory storage, no database or file storage yet.

## Introduction
There are five basic model:

- `user` defines the account
- `role` defines the role, which will be hold by `user`
- `permission` defines what actions can be performed on what resources, which will be hold by `role`
- `user_role` defines the relations between `user` and `role`
- `role_permission` defines the relations between `role` and `permission`

## Authentication and Authorization
The entrypoint RESTful API is

```
POST /signin
```

This will respond a token by your username and password, Take this token in each request header `Authorization`. 

## Usage
```go
go run main.go
```

Then request the `http://localhost/signin`

## License
[MIT License](LICENSE)