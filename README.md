# GINACL

Simple ACL for gin-gonic

## GIN USAGE

```
r.Use(
    GinAclMiddleware(func(c *gin.Context) string{
        return c.Get("API_USER")
    }, rm /* AclRoleMap */, r /* RuleSet */),
)

```