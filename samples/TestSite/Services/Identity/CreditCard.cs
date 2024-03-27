using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Web;

using MongoDB;
using MongoDB.Bson;
using MongoDB.Driver;

namespace TestSite.Services.Identity
{
    public class CreditCard
    {
        public CreditCard()
        {
            _id = ObjectId.GenerateNewId();
            _t = "CreditCard";

            FullName = string.Empty;
            CardTypeId = ObjectId.Empty;
            CardTypeName = string.Empty;
            Number = string.Empty;
            Expires = string.Empty;
            Zipcode = string.Empty;
            CVVCode = string.Empty;
        }

        public ObjectId _id { get; set; }
        public string _t { get; set; }
        public string FullName { get; set; }
        public ObjectId CardTypeId { get; set; }
        public string CardTypeName { get; set; }
        public string Number { get; set; }
        public string Expires { get; set; }
        public string Zipcode { get; set; }
        public string CVVCode { get; set; }
    }
}