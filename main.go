package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/jsonbruce/rbac/model"
	"github.com/jsonbruce/rbac/token"
	"github.com/jsonbruce/rbac/utils"
)

var (
	users           []model.User
	userRoles       []model.UserRole
	roles           []model.Role
	rolePermissions []model.RolePermission
	permissions     []model.Permission
)

func initData() {
	u := model.User{
		Model:    model.Model{UUID: uuid.New().String()},
		Username: "root",
		Password: "root",
	}
	u1 := model.User{
		Model:    model.Model{UUID: uuid.New().String()},
		Username: "user1",
		Password: "user1",
	}

	users = append(users, u)
	users = append(users, u1)

	r := model.Role{
		Model: model.Model{UUID: uuid.New().String()},
		Name:  "root",
	}
	r1 := model.Role{
		Model: model.Model{UUID: uuid.New().String()},
		Name:  "user",
	}

	roles = append(roles, []model.Role{r, r1}...)

	userRoles = append(userRoles, model.UserRole{
		Model:    model.Model{UUID: uuid.New().String()},
		UserUUID: u.UUID,
		RoleUUID: r.UUID,
	})
	userRoles = append(userRoles, model.UserRole{
		Model:    model.Model{UUID: uuid.New().String()},
		UserUUID: u1.UUID,
		RoleUUID: r1.UUID,
	})

	p := model.Permission{
		Model:    model.Model{UUID: uuid.New().String()},
		Action:   "*",
		Resource: "*",
	}
	p1 := model.Permission{
		Model:    model.Model{UUID: uuid.New().String()},
		Action:   http.MethodGet,
		Resource: "/users",
	}
	p2 := model.Permission{
		Model:    model.Model{UUID: uuid.New().String()},
		Action:   http.MethodGet,
		Resource: "/jobs",
	}
	p3 := model.Permission{
		Model:    model.Model{UUID: uuid.New().String()},
		Action:   http.MethodPost,
		Resource: "/jobs",
	}

	permissions = append(permissions, []model.Permission{p, p1, p2, p3}...)

	rolePermissions = append(rolePermissions, model.RolePermission{
		Model:          model.Model{UUID: uuid.New().String()},
		RoleUUID:       r.UUID,
		PermissionUUID: p.UUID,
	})
	rolePermissions = append(rolePermissions, model.RolePermission{
		Model:          model.Model{UUID: uuid.New().String()},
		RoleUUID:       r1.UUID,
		PermissionUUID: p2.UUID,
	})
	rolePermissions = append(rolePermissions, model.RolePermission{
		Model:          model.Model{UUID: uuid.New().String()},
		RoleUUID:       r1.UUID,
		PermissionUUID: p3.UUID,
	})
}

func initServer() {
	tokener := token.NewTokener()

	rbacModel := &model.RBACModel{
		Users:           users,
		Roles:           roles,
		Permissions:     permissions,
		UserRoles:       userRoles,
		RolePermissions: rolePermissions,
	}

	logger := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Println("@logger start")
			log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL.Path)

			next.ServeHTTP(w, r)
		})
	}

	timer := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Println("@timer start")

			timeStart := time.Now()

			next.ServeHTTP(w, r)

			log.Printf("Time Elapsed: %vms", time.Since(timeStart).Milliseconds())
		})
	}

	authentication := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Println("@authentication start")

			// Skip signin
			if r.Method == http.MethodPost && r.URL.Path == "/signin" {
				next.ServeHTTP(w, r)
				return
			}

			// Authentication
			// Check r.Header.Get("Authorization")
			authHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
			if len(authHeader) != 2 {
				utils.WriteResponse(w, utils.Response{
					Code:    403,
					Message: "Authentication Error. Malformed Token",
					Data:    nil,
				})
				return
			}

			uid, err := tokener.Verify(authHeader[1])
			if err != nil {
				utils.WriteResponse(w, utils.Response{
					Code:    403,
					Message: fmt.Sprintf("Authentication Error. %s", err.Error()),
					Data:    nil,
				})
				return
			}

			_, err = rbacModel.FindUserByUUID(uid)
			if err != nil {
				utils.WriteResponse(w, utils.Response{
					Code:    403,
					Message: "Authentication Error. Account not exist",
					Data:    nil,
				})
				return
			}

			// Access context values in handlers use r.Context().Value("uid")
			ctx := context.WithValue(r.Context(), "uid", uid)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	authorization := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Println("@authorization start")

			// Skip signin
			if r.Method == http.MethodPost && r.URL.Path == "/signin" {
				next.ServeHTTP(w, r)
				return
			}

			uid := r.Context().Value("uid").(string)

			// Authorization
			// Permission is action on resource
			// Action: r.Method
			// Resource: r.URL.Path
			if !rbacModel.HasPermission(uid, r.Method, r.URL.Path) {
				utils.WriteResponse(w, utils.Response{
					Code:    403,
					Message: fmt.Sprintf("Authorization Error. Your account has no permission do %s on %s", r.Method, r.RequestURI),
					Data:    nil,
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}

	serverMux := &http.ServeMux{}
	serverMux.HandleFunc("/signin", func(w http.ResponseWriter, r *http.Request) {
		requestData := &struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}{}

		if err := json.NewDecoder(r.Body).Decode(requestData); err != nil {
			utils.WriteResponse(w, utils.Response{
				Code:    500,
				Message: fmt.Sprintf("json decode: ", err.Error()),
				Data:    nil,
			})
			return
		}

		user, err := rbacModel.FindUserByUsername(requestData.Username)
		if err != nil {
			utils.WriteResponse(w, utils.Response{
				Code:    403,
				Message: fmt.Sprintf("find user: %s", err.Error()),
				Data:    nil,
			})
			return
		}

		if user.Password != requestData.Password {
			utils.WriteResponse(w, utils.Response{
				Code:    403,
				Message: fmt.Sprintf("password error"),
				Data:    nil,
			})
			return
		}

		userToken, err := tokener.Sign(user.UUID)
		if err != nil {
			utils.WriteResponse(w, utils.Response{
				Code:    50001,
				Message: err.Error(),
				Data:    nil,
			})
			return
		}

		utils.WriteResponse(w, utils.Response{
			Code:    0,
			Message: "",
			Data:    userToken,
		})
	})
	serverMux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		utils.WriteResponse(w, utils.Response{
			Code:    0,
			Message: "",
			Data:    users,
		})
	})
	serverMux.HandleFunc("/jobs", func(w http.ResponseWriter, r *http.Request) {
		utils.WriteResponse(w, utils.Response{
			Code:    0,
			Message: "",
			Data:    "jobs",
		})
	})

	server := &http.Server{
		Handler: logger(timer(authentication(authorization(serverMux)))),
	}

	log.Fatal(server.ListenAndServe())
}

func main() {
	initData()

	initServer()
}
