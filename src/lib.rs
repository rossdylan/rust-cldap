extern crate libc;
use libc::{c_int, c_uchar, c_char};
use std::ptr;
use std::ffi::CStr;
use std::mem;


#[repr(C)]
struct LDAP;
#[repr(C)]
struct LDAPMessage;
#[repr(C)]
struct timeval;


#[link(name = "ldap")]
extern {
    fn ldap_initialize(ldap: *const *mut LDAP, uri: *const c_uchar) -> c_int;
    fn ldap_err2string(err: c_int) -> *mut c_char;
    fn ldap_simple_bind_s(ldap: *const LDAP, who: *const c_uchar, pass: *const c_uchar) -> c_int;
    fn ldap_search_ext_s(ldap: *const LDAP, base: *const c_uchar, scope: c_int,
                         filter: *const c_uchar, attrs: *const *const c_uchar,
                         attrsonly: c_int, serverctrls: *const *mut LDAPControl,
                         clientctrls: *const *mut LDAPControl, timeout: *const timeval,
                         sizelimit: c_int, res: *const *const LDAPMessage) -> c_int;
}

struct RustLDAP {
    ldap: Box<LDAP>,
    ldap_ptr: *const LDAP,
}

impl RustLDAP {

    /// Create a new RustLDAP struct and use an ffi call to ldap_initialize to
    /// allocate and init a c LDAP struct. All of that is hidden inside of
    /// RustLDAP.
    fn new(uri: &str) -> Result<RustLDAP, &str> {
        unsafe {
            let cldap = Box::from_raw(ptr::null_mut());
            let ldap_ptr_ptr: *const *mut LDAP = &Box::into_raw(cldap);
            let res = ldap_initialize(ldap_ptr_ptr, uri.as_ptr());
            if res != 0 {
                let raw_estr = ldap_err2string(res as c_int);
                return Err(CStr::from_ptr(raw_estr)
                           .to_str()
                           .unwrap());
            }
            let new_ldap = RustLDAP {
                ldap: Box::from_raw(*ldap_ptr_ptr),
                ldap_ptr: *ldap_ptr_ptr,
            };
            Ok(new_ldap)
        }
    }

    /// Perform a synchronos simple bind (ldap_simple_bind_s). The result is
    /// either Ok(LDAP_SUCCESS) or Err(ldap_err2string).
    fn simple_bind(&self, who: &str, pass: &str) -> Result<i64, &str> {
        let res = unsafe { ldap_simple_bind_s(self.ldap_ptr, who.as_ptr(), pass.as_ptr()) as i64};
        if res < 0 {
            let raw_estr = unsafe { ldap_err2string(res as c_int) };
            return Err(unsafe { CStr::from_ptr(raw_estr).to_str().unwrap() });
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    /// Test creating a RustLDAP struct with a valid uri.
    #[test]
    fn test_ldap_new() {
        let ldap = super::RustLDAP::new("ldap://localhost");
        match ldap {
            Ok(_) => assert!(true),
            Err(_) => {
                assert!(false);
            }
        }
    }

    /// Test creating a RustLDAP struct with an invalid uri.
    #[test]
    fn test_invalid_ldap_new() {
        let ldap = super::RustLDAP::new("lda://localhost");
        match ldap {
            Ok(_) => assert!(false),
            Err(es) => {
                assert_eq!("Bad parameter to an ldap routine", es);
            }
        }
    }

    #[test]
    fn test_simple_bind() {
        let ldap_res = super::RustLDAP::new("ldap://localhost");
        match ldap_res {
            Ok(ldap) => {
                let res = ldap.simple_bind("uid=testerson,ou=Test,dc=example,dc=com", "fakepass");
                println!("{:?}", res);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

}
