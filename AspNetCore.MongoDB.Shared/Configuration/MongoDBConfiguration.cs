using MongoDB.Driver;

namespace AspNetCore.MongoDB.Shared.Configuration
{
    public class MongoDBConfiguration
    {
        public string ConnectionString { get; set; }
        public string Database {get; set; }    
        public SslSettings SslSettings { get; set; }
    }
}
