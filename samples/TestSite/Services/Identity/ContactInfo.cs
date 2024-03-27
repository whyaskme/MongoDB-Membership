﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

using MongoDB;
using MongoDB.Bson;
using MongoDB.Driver;

namespace TestSite.Services.Identity
{
    public class ContactInfo
    {
        public ContactInfo()
        {
            Address = new List<Address>();
            Email = new List<Email>();
            Phone = new List<Phone>();
        }

        public List<Address> Address { get; set; }
        public List<Email> Email { get; set; }
        public List<Phone> Phone { get; set; }
    }
}