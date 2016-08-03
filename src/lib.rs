extern crate libc;
use libc::{c_int, c_uchar, c_char, c_void, timeval};
use std::ptr;
use std::ffi::{CStr, CString};
use std::collections::HashMap;
use std::slice;

pub mod codes;

// Define the structs used by the ldap c library.
#[repr(C)]
struct LDAP;
#[repr(C)]
struct LDAPMessage;
#[repr(C)]
pub struct LDAPControl;
#[repr(C)]
struct BerElement;

#[link(name = "lber")]
#[allow(improper_ctypes)]
extern {
    fn ber_free(ber: *const BerElement, freebuf: c_int);
}

#[link(name = "ldap")]
#[allow(improper_ctypes)]
extern {
    fn ldap_initialize(ldap: *const *mut LDAP, uri: *const c_uchar) -> c_int;
    fn ldap_memfree(p: *const c_void);
    fn ldap_err2string(err: c_int) -> *mut c_char;
    fn ldap_first_entry(ldap: *const LDAP, result: *const LDAPMessage) -> *const LDAPMessage;
    fn ldap_next_entry(ldap: *const LDAP, entry: *const LDAPMessage) -> *const LDAPMessage;
    fn ldap_get_values(ldap: *const LDAP, entry: *const LDAPMessage, attr: *const c_char) -> *const *const c_char;
    fn ldap_count_values(vals: *const *const c_char) -> c_int;
    fn ldap_value_free(vals: *const *const c_char);

    fn ldap_simple_bind_s(ldap: *const LDAP, who: *const c_uchar, pass: *const c_uchar) -> c_int;
    fn ldap_first_attribute(ldap: *const LDAP, entry: *const LDAPMessage, berptr: *const *const BerElement) -> *const c_char;
    fn ldap_next_attribute(ldap: *const LDAP, entry: *const LDAPMessage, berptr: *const BerElement) -> *const c_char;
    fn ldap_search_ext_s(ldap: *const LDAP, base: *const c_uchar, scope: c_int,
                         filter: *const c_uchar, attrs: *const *const c_uchar,
                         attrsonly: c_int, serverctrls: *const *const LDAPControl,
                         clientctrls: *const *const LDAPControl, timeout: *const timeval,
                         sizelimit: c_int, res: *const *mut LDAPMessage) -> c_int;
}

pub struct RustLDAP {
    // Have a heap allocated box for our LDAP instance
    _ldap: Box<LDAP>,
    // Have the raw pointer to it so we can pass it into internal functions
    ldap_ptr: *const LDAP,
}


impl RustLDAP {
    /// Create a new RustLDAP struct and use an ffi call to ldap_initialize to
    /// allocate and init a c LDAP struct. All of that is hidden inside of
    /// RustLDAP.
    pub fn new(uri: &str) -> Result<RustLDAP, &str> {
        unsafe {
            let cldap = Box::from_raw(ptr::null_mut());
            let ldap_ptr_ptr: *const *mut LDAP = &Box::into_raw(cldap);
            let res = ldap_initialize(ldap_ptr_ptr, uri.as_ptr());
            if res != codes::results::LDAP_SUCCESS {
                let raw_estr = ldap_err2string(res as c_int);
                return Err(CStr::from_ptr(raw_estr)
                           .to_str()
                           .unwrap());
            }
            let new_ldap = RustLDAP {
                _ldap: Box::from_raw(*ldap_ptr_ptr),
                ldap_ptr: *ldap_ptr_ptr,
            };
            Ok(new_ldap)
        }
    }

    /// Perform a synchronos simple bind (ldap_simple_bind_s). The result is
    /// either Ok(LDAP_SUCCESS) or Err(ldap_err2string).
    pub fn simple_bind(&self, who: &str, pass: &str) -> Result<i64, &str> {
        let res = unsafe { ldap_simple_bind_s(self.ldap_ptr, who.as_ptr(), pass.as_ptr()) as i64};
        if res < 0 {
            let raw_estr = unsafe { ldap_err2string(res as c_int) };
            return Err(unsafe { CStr::from_ptr(raw_estr).to_str().unwrap() });
        }
        Ok(res)
    }

    pub fn simple_search(&self, base: &str, scope: i32) -> Result<Vec<HashMap<String,Vec<String>>>, &str> {
        self.ldap_search(base, scope, None, None, false, None, None, ptr::null(), -1)
    }

    /// Expose a not very 'rust-y' api for ldap_search_ext_s. Ideally this will
    /// be used mainly internally and a simpler api is exposed to users.
    pub fn ldap_search(&self, base: &str, scope: i32, filter: Option<&str>, attrs: Option<Vec<&str>>, attrsonly: bool,
					serverctrls: Option<*const *const LDAPControl>, clientctrls: Option<*const *const LDAPControl>,
					timeout: *const timeval, sizelimit: i32)
					-> Result<Vec<HashMap<String,Vec<String>>>, &str> {

        // Allocate a boxed pointer for our ldap message. We will need to call
        // ldap_msgfree on the raw pointer after we are done, and then
        // make sure the box is deallocated
        let ldap_msg = unsafe { Box::from_raw(ptr::null_mut()) };
        let raw_msg: *const *mut LDAPMessage = &Box::into_raw(ldap_msg);

        let r_filter = match filter {
            Some(fs) => fs.as_ptr(),
            None    => ptr::null()
        };

        let mut r_attrs: *const *const c_uchar = ptr::null();
        
        let mut c_strs: Vec<CString> = Vec::new();
        let mut r_attrs_ptrs: Vec<*const c_uchar> = Vec::new();

        if let Some(strs) = attrs {
            for string in strs {

                //create new CString and take ownership of it in c_strs
                c_strs.push(CString::new(string).unwrap());

                //create a pointer to that CString's raw data and store it in r_attrs
                r_attrs_ptrs.push(c_strs[c_strs.len() - 1].as_ptr() as *const c_uchar);
            }
            r_attrs = r_attrs_ptrs.as_ptr();
        }

        let r_serverctrls = match serverctrls {
            Some(sc) => sc,
            None => ptr::null()
        };

        let r_clientctrls = match clientctrls {
            Some(cc) => cc,
            None => ptr::null()
        };

        let res: i32 = unsafe { ldap_search_ext_s(self.ldap_ptr,
                                                  base.as_ptr(),
                                                  scope as c_int,
                                                  r_filter,
                                                  r_attrs,
                                                  attrsonly as c_int,
                                                  r_serverctrls,
                                                  r_clientctrls,
                                                  timeout,
                                                  sizelimit as c_int,
                                                  raw_msg) };
        if res != codes::results::LDAP_SUCCESS {
            let raw_estr = unsafe { ldap_err2string(res as c_int) };
            return Err(unsafe { CStr::from_ptr(raw_estr).to_str().unwrap() });
        }
        let mut resvec: Vec<HashMap<String,Vec<String>>> = vec![];
        let mut entry = unsafe { ldap_first_entry(self.ldap_ptr, *raw_msg) };
        loop {
            if entry.is_null() {
                break;
            }
            let mut map: HashMap<String,Vec<String>> = HashMap::new();
            let ber: *const BerElement = ptr::null();
            let mut attr: *const c_char = unsafe {
                ldap_first_attribute(self.ldap_ptr, entry, &ber)
            };
            loop {
                if attr.is_null() {
                    break;
                }
                unsafe {
                    // This fun bit of code ensures that we copy the c string for
                    // the attribute into an owned string. This is important since
                    // we use ldap_memfree just below this to free the memory on the
                    // c side of things.
                    let tmp: String = CStr::from_ptr(attr)
                        .to_str()
                        .unwrap()
                        .to_owned();
                    let raw_vals: *const *const c_char = ldap_get_values(
                        self.ldap_ptr,
                        entry,
                        attr);
                    let raw_vals_len = ldap_count_values(raw_vals) as usize;
                    let val_slice: &[*const c_char] = slice::from_raw_parts(
                        raw_vals,
                        raw_vals_len);
                    let values: Vec<String> = val_slice.iter().map(|ptr| {
                        CStr::from_ptr(*ptr)
                            .to_str()
                            .unwrap()
                            .to_owned()}).collect();
                    map.insert(tmp, values);
                    ldap_value_free(raw_vals);
                    ldap_memfree(attr as *const c_void);
                    attr = ldap_next_attribute(self.ldap_ptr, entry, ber)
                }
            }
            unsafe { ber_free(ber, 0) };
            resvec.push(map);
            entry = unsafe { ldap_next_entry(self.ldap_ptr, entry) };
        }
        Ok(resvec)
    }
}

#[cfg(test)]
mod tests {
    use codes;
    /// Test creating a RustLDAP struct with a valid uri.
    #[test]
    fn test_ldap_new() {
        let ldap = super::RustLDAP::new("ldap://ldapproxy1.csh.rit.edu");
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
        let ldap_res = super::RustLDAP::new("ldaps://ldap.csh.rit.edu");
        match ldap_res {
            Ok(ldap) => {
                let res = ldap.simple_bind("uid=test4,ou=Users,dc=csh,dc=rit,dc=edu", "fakepass");
                println!("{:?}", res);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn test_simple_search() {
        println!("Testing search");
        let ldap_res = super::RustLDAP::new("ldap://ldapproxy1.csh.rit.edu");
        match ldap_res {
            Ok(ldap) => {
                let res = ldap.simple_bind("uid=test4,ou=Users,dc=csh,dc=rit,dc=edu", "fake");
                println!("{:?}", res);
                let search_res = ldap.simple_search("uid=rossdylan,ou=Users,dc=csh,dc=rit,dc=edu", codes::scopes::LDAP_SCOPE_BASE);
                println!("{:?}", search_res);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }
}
