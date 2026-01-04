namespace CertificatedDemo.Models
{
    public static class Permissions
    {
        // Product Permissions
        public const string ProductsView = "Products.View";
        public const string ProductsCreate = "Products.Create";
        public const string ProductsEdit = "Products.Edit";
        public const string ProductsDelete = "Products.Delete";

        // User Management Permissions
        public const string UsersView = "Users.View";
        public const string UsersManage = "Users.Manage";
        public const string RolesManage = "Roles.Manage";

        // Certificate Permissions
        public const string CertificatesView = "Certificates.View";
        public const string CertificatesManage = "Certificates.Manage";
        public const string DocumentSign = "Document.Sign";
        public const string CodeSign = "Code.Sign";

        // All permissions as list
        public static List<string> GetAllPermissions()
        {
            return new List<string>
        {
            ProductsView, ProductsCreate, ProductsEdit, ProductsDelete,
            UsersView, UsersManage, RolesManage,
            CertificatesView, CertificatesManage, DocumentSign, CodeSign
        };
        }

        // Permission groups for roles
        public static Dictionary<string, List<string>> RolePermissions = new()
        {
            ["Admin"] = new List<string>
        {
            ProductsView, ProductsCreate, ProductsEdit, ProductsDelete,
            UsersView, UsersManage, RolesManage,
            CertificatesView, CertificatesManage, DocumentSign, CodeSign
        },
            ["Manager"] = new List<string>
        {
            ProductsView, ProductsCreate, ProductsEdit,
            UsersView,
            CertificatesView, DocumentSign
        },
            ["User"] = new List<string>
        {
            ProductsView,
            CertificatesView
        }
        };
    }

    public static class Roles
    {
        public const string Admin = "Admin";
        public const string Manager = "Manager";
        public const string User = "User";

        public static List<string> GetAllRoles()
        {
            return new List<string> { Admin, Manager, User };
        }
    }


}
