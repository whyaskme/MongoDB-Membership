using AspNetCore.Identity.Mongo.Model;
using MongoDB.Bson.Serialization.Attributes;
using System.Collections.Generic;
using System;
using TestSite.Services.Identity;
using MongoDB.Bson;
using System.Security.Cryptography;

namespace SampleSite.Identity
{
    [BsonIgnoreExtraElements]
    public class MongoDbUser : MongoUser
    {
        public MongoDbUser()
        {
            Id = ObjectId.GenerateNewId();
            Profile = new Profile();
        }

        //public ObjectId _id { get; set; }
        public Profile Profile { get; set; }
    }
}
