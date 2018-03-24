// ReSharper disable once CheckNamespace
namespace Microsoft.AspNetCore.Authentication
{
    public class AzureAdOptions
    {
        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string Instance { get; set; }

        public string Domain { get; set; }

        public string TenantId { get; set; }

        public string CallbackPath { get; set; }
        public string Resource { get; set; }
        public string EmbedUrlBase { get; set; }
    }
}