using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;

namespace CookieManager
{
   /// <summary>
   /// Implementation of <see cref="ICookie" /> 
   /// </summary>
   /// <remarks>
   /// External depedenacy of <see cref="IHttpContextAccessor" /> 
   /// </remarks>
   /// <param name="httpContextAccessor">IHttpAccessor</param>
   /// <param name="dataProtectionProvider">data protection provider</param>
   /// <param name="optionAccessor">cookie manager option accessor</param>
   public class HttpCookie(IHttpContextAccessor httpContextAccessor,
    IDataProtectionProvider dataProtectionProvider,
    IOptions<CookieManagerOptions> optionAccessor) : ICookie
   {
      private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;
      private readonly IDataProtector _dataProtector = dataProtectionProvider.CreateProtector(Purpose);
      private static readonly string Purpose = "CookieManager.Token.v1";
      private readonly CookieManagerOptions _cookieManagerOptions = optionAccessor.Value;
      private readonly ChunkingHttpCookie _chunkingHttpCookie = new(optionAccessor);

      public ICollection<string> Keys
      {
         get
         {
            if (_httpContextAccessor.HttpContext == null)
            {
               throw new ArgumentNullException(nameof(_httpContextAccessor.HttpContext));
            }

            return _httpContextAccessor.HttpContext.Request.Cookies.Keys;
         }
      }

      public bool Contains(string key)
      {
         //if (_httpContextAccessor.HttpContext == null)
         //{
         //   throw new ArgumentNullException(nameof(_httpContextAccessor.HttpContext));
         //}
         ArgumentNullException.ThrowIfNull(_httpContextAccessor.HttpContext);

         ArgumentNullException.ThrowIfNull(key);

         return _httpContextAccessor.HttpContext.Request.Cookies.ContainsKey(key);
      }

      /// <summary>
      /// Get the key value
      /// </summary>
      /// <param name="key">Key</param>
      /// <returns>value</returns>
      public string Get(string key)
      {
         //if (_httpContextAccessor.HttpContext == null)
         //{
         //   throw new ArgumentNullException(nameof(_httpContextAccessor.HttpContext));
         //}
         ArgumentNullException.ThrowIfNull(_httpContextAccessor.HttpContext);

         ArgumentNullException.ThrowIfNull(key);

         if (Contains(key))
         {
            var encodedValue = _chunkingHttpCookie.GetRequestCookie(_httpContextAccessor.HttpContext, key);
            //allow encryption is optional
            //may change the allow encryption to avoid this first check if cookie value is able to decode than unprotect tha data
            if (Base64TextEncoder.TryDecode(encodedValue, out string protectedData))
            {
               if (_dataProtector.TryUnprotect(protectedData, out string unprotectedData))
               {
                  return unprotectedData;
               }
            }
            return encodedValue;
         }

         return string.Empty;
      }

      /// <summary>
      /// Remove the cookie key
      /// </summary>
      /// <param name="key">Key</param>
      public void Remove(string key)
      {
         //if (_httpContextAccessor.HttpContext == null)
         //{
         //   throw new ArgumentNullException(nameof(_httpContextAccessor.HttpContext));
         //}
         ArgumentNullException.ThrowIfNull(_httpContextAccessor.HttpContext);

         ArgumentNullException.ThrowIfNull(key);

         ChunkingHttpCookie.RemoveCookie(_httpContextAccessor.HttpContext, key);
      }

      /// <summary>
      /// set the cookie
      /// </summary>
      /// <param name="key">unique key</param>
      /// <param name="value">value to store</param>
      /// <param name="expireTime">Expire time (default time is 10 millisencond)</param>
      public void Set(string key, string value, int? expireTime)
      {
         ////validate input
         //if (_httpContextAccessor.HttpContext == null)
         //{
         //   throw new ArgumentNullException(nameof(_httpContextAccessor.HttpContext));
         //}
         ArgumentNullException.ThrowIfNull(_httpContextAccessor.HttpContext);

         ArgumentException.ThrowIfNullOrEmpty(key);

         Set(key, value, null, expireTime);
      }

      /// <summary>
      /// set the cookie 
      /// </summary>
      /// <param name="key">key</param>
      /// <param name="value">value of the specified key</param>
      /// <param name="option">CookieOption</param>
      public void Set(string key, string value, CookieOptions option)
      {
         //if (_httpContextAccessor.HttpContext == null)
         //{
         //   throw new ArgumentNullException(nameof(_httpContextAccessor.HttpContext));
         //}
         ArgumentNullException.ThrowIfNull(_httpContextAccessor.HttpContext);

         ArgumentNullException.ThrowIfNull(key);

         ArgumentNullException.ThrowIfNull(option);

         Set(key, value, option, null);
      }

      private void Set(string key, string value, CookieOptions option, int? expireTime)
      {
         if (option == null)
         {
            option = new CookieOptions();

            if (expireTime.HasValue)
               option.Expires = DateTime.Now.AddMinutes(expireTime.Value);
            else
               option.Expires = DateTime.Now.AddDays(_cookieManagerOptions.DefaultExpireTimeInDays);
         }

         //check for encryption 
         if (_cookieManagerOptions.AllowEncryption)
         {
            string protecetedData = _dataProtector.Protect(value);
            var encodedValue = Base64TextEncoder.Encode(protecetedData);
            _chunkingHttpCookie.AppendResponseCookie(_httpContextAccessor.HttpContext, key, encodedValue, option);
         }
         else
         {
            //just append the cookie 
            _chunkingHttpCookie.AppendResponseCookie(_httpContextAccessor.HttpContext, key, value, option);
         }

      }
   }
}
