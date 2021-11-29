package model

import "github.com/jsonbruce/rbac/utils"

type RBACModel struct {
	Users           []User
	Roles           []Role
	Permissions     []Permission
	UserRoles       []UserRole
	RolePermissions []RolePermission
}

func (rm *RBACModel) FindPermissionByUUID(uuid string) (Permission, error) {
	for _, permission := range rm.Permissions {
		if permission.UUID == uuid {
			return permission, nil
		}
	}
	return Permission{}, utils.ErrorNotFound
}

func (rm *RBACModel) FindUserByUsername(un string) (User, error) {
	for _, user := range rm.Users {
		if user.Username == un {
			return user, nil
		}
	}
	return User{}, utils.ErrorNotFound
}

func (rm *RBACModel) FindUserByUUID(uuid string) (User, error) {
	for _, user := range rm.Users {
		if user.UUID == uuid {
			return user, nil
		}
	}
	return User{}, utils.ErrorNotFound
}

func (rm *RBACModel) GetUserRoleByUUID(uuid string) (string, error) {
	for _, role := range rm.UserRoles {
		if role.UserUUID == uuid {
			for _, r := range rm.Roles {
				if r.UUID == role.RoleUUID {
					return r.Name, nil
				}
			}
		}
	}

	return "", utils.ErrorNotFound
}

func (rm *RBACModel) HasPermission(uuid, action, resource string) bool {
	// Get role
	roleUUID := ""

	for _, ur := range rm.UserRoles {
		if ur.UserUUID == uuid {
			roleUUID = ur.RoleUUID
			break
		}
	}

	// All permissions this account has
	ps := []Permission{}
	for _, rp := range rm.RolePermissions {
		if rp.RoleUUID == roleUUID {
			puid := rp.PermissionUUID
			p, e := rm.FindPermissionByUUID(puid)
			if e == nil {
				ps = append(ps, p)
			}
		}
	}

	for _, p := range ps {
		if p.Action == "*" && p.Resource == "*" {
			return true
		}

		if p.Action == action && p.Resource == resource {
			return true
		}
	}

	return false
}
