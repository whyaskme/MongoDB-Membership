using AspNetCore.Identity.Mongo.Model;
using MongoDB.Bson.Serialization.Attributes;
using System.Collections.Generic;
using System;
using TestSite.Services.Identity;

namespace SampleSite.Identity
{
    [BsonIgnoreExtraElements]
    public class TestSiteUser : MongoUser
    {
        public TestSiteUser()
        {
            Profile = new Profile();
        }

        public Profile Profile { get; set; }
    }
}
