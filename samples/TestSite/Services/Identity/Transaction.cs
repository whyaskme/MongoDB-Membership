﻿using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Web;

using MongoDB;
using MongoDB.Bson;
using MongoDB.Driver;

namespace TestSite.Services.Identity
{
    public class Transaction
    {
        public Transaction()
        {
            _id = ObjectId.GenerateNewId();
            _t = "CreditCard";
            Date = DateTime.UtcNow;
            Type = string.Empty;
            Amount = 0.00;
            ProcessorId = ObjectId.Empty;
            PaymentMethodId = null;
            ResultCode = 0;
            ResultName = string.Empty;
            ResultDetails = string.Empty;
            PaymentCard = new CreditCard();
        }

        public ObjectId _id { get; set; }
        public string _t { get; set; }
        public DateTime Date { get; set; }
        public string Type { get; set; }
        public double Amount { get; set; }
        public ObjectId ProcessorId { get; set; }
        public object PaymentMethodId { get; set; }
        public short ResultCode { get; set; }
        public string ResultName { get; set; }
        public string ResultDetails { get; set; }
        public CreditCard PaymentCard { get; set; }
    }
}