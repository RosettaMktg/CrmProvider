﻿using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.Services;
using System.Linq;
using System.Runtime.Serialization;
using System.Web;
using System.Web.Security;
using System.Web.Configuration;
using System.Collections.Specialized;

using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Client;
using Microsoft.Xrm.Sdk.Query;
using Microsoft.Xrm.Sdk.Client;
using Microsoft.Xrm.Sdk.Discovery;
using Microsoft.Xrm.Client.Services;
using Microsoft.Xrm.Sdk.Metadata;


public class CRMMembershipProvider : MembershipProvider
{
    private Guid _accountId;
    private string _passwordN;
    private string _usernameN;
    private string _securityQuestionN;
    private string _securityAnswerN;
    private string _emailN;
    private bool _onlineN;
    private bool _lockN;
    private int _loginAttemptsN;
    private DateTime _timeLockedN;
    private DateTime _firstFailedN;
    private DateTime _lastLoginTimeN;
    private DateTime _accountCreationN;
    
    //our connection method
    public OrganizationService OurConnect() {
        var connection = new CrmConnection(_ConnectionStringName);
        var service = new OrganizationService(connection);
        return service;
    }

    public override string ApplicationName
    {
        get
        {
            return _ApplicationName;
        }
        set
        {
            _ApplicationName = value;
        }
    }

    public override bool ChangePassword(string username, string oldPassword, string newPassword)
    {//tc
        var service = OurConnect();
        //find user by username
        //create condition for query
        ConditionExpression c = new ConditionExpression();
        c.AttributeName = "rosetta_username";
        c.Operator = ConditionOperator.Equal;
        c.Values.Add(username);

        FilterExpression f = new FilterExpression();
        f.Conditions.Add(c);

        QueryExpression q = new QueryExpression("rosetta_useraccount");
        q.ColumnSet.AddColumn("rosetta_password");
        q.Criteria.AddFilter(f);

        EntityCollection result = service.RetrieveMultiple(q);
        //compare oldPassword to the current pasword
        if (oldPassword != (string)result.Entities[0]["rosetta_password"])//assuming that entities[0] is the only entity since i am only making onw with my query
        {
            throw new Exception("no user/pass match");
        }
        //if the same overwrite with new password
        else {

            return true;
        }
    }

    public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
    {
        return false;
    }
    //MAS
    public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
    {
        var service = OurConnect(); //intialize connection

        ConditionExpression condition = new ConditionExpression(); //create new condition
        condition.AttributeName = "rosetta_username"; //column we want to check against
        condition.Operator = ConditionOperator.Equal; //checking against equal values
        condition.Values.Add(username); //check username against rosetta_username in CRM

        FilterExpression filter = new FilterExpression(); //create new filter for the condition
        filter.Conditions.Add(condition); //add condition to the filter

        QueryExpression query = new QueryExpression("rosetta_useraccount"); //create new query
        //query.ColumnSet.AddColumns("rosetta_username"); <--commented because do not need in this situation-->
        query.Criteria.AddFilter(filter); //query CRM with the new filter for username
        EntityCollection ec = service.RetrieveMultiple(query); //retrieve all records with same username

        if (ec.Entities.Count != 0)
        {
            throw new Exception("Username already exists!");
        }
        else
        {
            Entity newMember = new Entity("rosetta_useraccount");

            newMember["rosetta_name"] = username;
            newMember["rosetta_username"] = username;
            newMember["rosetta_password"] = password;
            newMember["rosetta_email"] = email;
            newMember["rosetta_securityquestion"] = passwordQuestion;
            newMember["rosetta_securityanswer"] = passwordAnswer;

            Guid entityID = service.Create(newMember);
            throw new Exception("Created new member!");
            //return GetUser(username);
        }
        /*foreach (Entity act in ec.Entities)
        {
            Console.WriteLine("account name:" + act["name"]);
            Console.WriteLine("primary contact first name:" + act["primarycontact.firstname"]);
            Console.WriteLine("primary contact last name:" + act["primarycontact.lastname"]);
        }*/

        
    }

    public override bool DeleteUser(string username, bool deleteAllRelatedData)
    {
        throw new NotImplementedException();
    }

    public override bool EnablePasswordReset
    {
        get { return _EnablePasswordReset; }
    }

    public override bool EnablePasswordRetrieval
    {
        get { return _EnablePasswordRetrieval; }
    }

    public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
    {//JH

        var service = OurConnect(); //intialize connection

        ConditionExpression condition = new ConditionExpression(); //creates a new condition.
        condition.AttributeName = "rosetta_email"; //column we want to check against
        condition.Operator = ConditionOperator.Equal; //checking against equal values
        condition.Values.Add(emailToMatch); //check username against rosetta_email in CRM
        FilterExpression filter = new FilterExpression(); //create new filter for the condition
        filter.Conditions.Add(condition); //add condition to the filter
        QueryExpression query = new QueryExpression("rosetta_useraccount"); //create new query
        query.ColumnSet.AllColumns = true;
        query.Criteria.AddFilter(filter); //query CRM with the new filter for email
        EntityCollection FoundRecordsByEmail = service.RetrieveMultiple(query); //retrieve all records with same email

        if (FoundRecordsByEmail.TotalRecordCount != 0)
        {
            MembershipUserCollection usersToReturn = new MembershipUserCollection();
            //usersToReturn.
            //return(//todo: need to figure out how to return the MembershipUserColletctions;
        }
        else
        {
            throw new NotImplementedException();
        }


        
    }

    public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
    {

        throw new NotImplementedException();
    }

    public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
    {
        throw new NotImplementedException();
    }

    public override int GetNumberOfUsersOnline()
    {
        throw new NotImplementedException();
    }

    public override string GetPassword(string username, string answer)
    {
        //var connection = new CrmConnection(_ConnectionString);
        //var service = new OrganizationService(connection);
        //var context = new CrmOrganizationServiceContext(connection);

        //service.RetrieveEntity(
        /*
        if (EnablePasswordRetrieval)
        {
            if (_PasswordFormat == MembershipPasswordFormat.Hashed)
            {
                throw new NotSupportedException("Cannot retrieve hashed passwords.");
            }
            else
            {
                //using direct from help file on Update using Entity Class

                OrganizationServiceProxy _proxyService;
                IOrganizationService _orgService;

                Guid _accountId;


                Entity account = new Entity("account");

                account = 
            }
        }
        else
        {
            throw new NotSupportedException("The current settings do not allow the password to be retrieved.");
        }
         */
        throw new NotImplementedException();
    }

    public override MembershipUser GetUser(string username, bool userIsOnline)
    {
        throw new NotImplementedException();
    }

    public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
    {
        throw new NotImplementedException();
    }

    public override string GetUserNameByEmail(string email)
    {
        throw new NotImplementedException();
    }

    public override int MaxInvalidPasswordAttempts
    {
        get { return _MaxInvalidPasswordAttempts; }
    }

    public override int MinRequiredNonAlphanumericCharacters
    {
        get { return _MinRequiredNonalphanumericCharacters; }
    }
    public override int MinRequiredPasswordLength
    {
        get { return _MinRequiredPasswordLength; } 
    }

    public override int PasswordAttemptWindow
    {
        get { return _PasswordAttemptWindow; }
    }

    public override MembershipPasswordFormat PasswordFormat
    {
        get { return _PasswordFormat; }
    }

    public override string PasswordStrengthRegularExpression
    {
        get { return _PasswordStrengthRegularExpression; }
    }

    public override bool RequiresQuestionAndAnswer
    {
        get { return _RequiresQuestionAndAnswer; }
    }

    public override bool RequiresUniqueEmail
    {
        get { return _RequireUniqueEmail; }
    }

    public override string ResetPassword(string username, string answer)
    {
        throw new NotImplementedException();
    }

    public override bool UnlockUser(string userName)
    {
        throw new NotImplementedException();
    }

    public override void UpdateUser(MembershipUser user)
    {
        throw new NotImplementedException();
    }

    public override bool ValidateUser(string username, string password)
    {
        throw new NotImplementedException();
    }
    /*Start of Initialize method*/
    private string GetConfigValue(string configValue, string defaultValue)
    {
        if (string.IsNullOrEmpty(configValue))
            return defaultValue;
        return configValue;
    }
    private string _ApplicationName;
    private bool _EnablePasswordReset;
    private bool _EnablePasswordRetrieval = false;
    private bool _RequiresQuestionAndAnswer = false;
    private bool _RequireUniqueEmail = true;
    private int _MaxInvalidPasswordAttempts;
    private int _PasswordAttemptWindow;
    private int _MinRequiredPasswordLength;
    private int _MinRequiredNonalphanumericCharacters;
    private string _PasswordStrengthRegularExpression;
    private MembershipPasswordFormat _PasswordFormat = MembershipPasswordFormat.Hashed;

    private string _ConnectionStringName;
   // private string _ConnectionString;


    public override void Initialize(string name, NameValueCollection config)
    {
        if (config == null)
            throw new ArgumentNullException("config");

        if (name == null || name.Length == 0)
            name = "CustomMembershipProvider";

        if (String.IsNullOrEmpty(config["description"]))
        {
            config.Remove("description");
            config.Add("description", "Custom Membership Provider");
        }

        base.Initialize(name, config);

        _ApplicationName = GetConfigValue(config["applicationName"],
                      System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
        _MaxInvalidPasswordAttempts = Convert.ToInt32(
                      GetConfigValue(config["maxInvalidPasswordAttempts"], "5"));
        _PasswordAttemptWindow = Convert.ToInt32(
                      GetConfigValue(config["passwordAttemptWindow"], "10"));
        _MinRequiredNonalphanumericCharacters = Convert.ToInt32(
                      GetConfigValue(config["minRequiredNonalphanumericCharacters"], "1"));
        _MinRequiredPasswordLength = Convert.ToInt32(
                      GetConfigValue(config["minRequiredPasswordLength"], "6"));
        _EnablePasswordReset = Convert.ToBoolean(
                      GetConfigValue(config["enablePasswordReset"], "true"));
        _PasswordStrengthRegularExpression = Convert.ToString(
                       GetConfigValue(config["passwordStrengthRegularExpression"], ""));
        _ConnectionStringName = Convert.ToString(
            GetConfigValue(config["connectionStringName"], "")); //todo: default to exception

        //An idea on how to use the connection string to dynamically connect our Library to the connection
        //_ConnectionString = ConfigurationManager.ConnectionStrings[_ConnectionStringName].ConnectionString;


    }
}