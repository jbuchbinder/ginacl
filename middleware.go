package ginacl

import (
	"github.com/gin-gonic/gin"
)

func GinAclMiddleware(tfunc func(c *gin.Context) string, rm AclRoleMap, r RuleSet) gin.HandlerFunc {
	return func(c *gin.Context) {
		t := tfunc(c)
		target := rm.FindRoles(t)
		if !r.ParseACL(c.FullPath(), target) {
			c.AbortWithStatusJSON(401, "{}")
			return
		}
		c.Next()
	}
}
