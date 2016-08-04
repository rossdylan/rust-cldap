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
			let uri_cstring = CString::new(uri).unwrap();
			let uri_ptr = uri_cstring.as_ptr() as *const u8;
            let res = ldap_initialize(ldap_ptr_ptr, uri_ptr);
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

        let filter_cstr: CString;

        let r_filter = match filter {
            Some(fs) => {
                filter_cstr = CString::new(fs).unwrap();
                filter_cstr.as_ptr() as *const u8
            },
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
            r_attrs_ptrs.push(ptr::null()); //ensure that there is a null value at the end of the vec
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

        let base = CString::new(base).unwrap();

        let res: i32 = unsafe { ldap_search_ext_s(self.ldap_ptr,
                                                  base.as_ptr() as *const u8,
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

	use std::ptr;
    use codes;

	const TEST_ADDRESS: &'static str 				= "ldap://ldap.forumsys.com";
	const TEST_BIND_DN: &'static str 				= "cn=read-only-admin,dc=example,dc=com";
	const TEST_BIND_PASS: &'static str				= "password";
	const TEST_SIMPLE_SEARCH_QUERY: &'static str 	= "uid=tesla,dc=example,dc=com";
	const TEST_SEARCH_BASE: &'static str 			= "ou=mathematicians,dc=example,dc=com";
	const TEST_SEARCH_FILTER: &'static str 			= "(cn=euler)";

    /// Test creating a RustLDAP struct with a valid uri.
    #[test]
    fn test_ldap_new(){

        let _ = super::RustLDAP::new(TEST_ADDRESS).unwrap();

    }

    /// Test creating a RustLDAP struct with an invalid uri.
    #[test]
    fn test_invalid_ldap_new(){

		if let Err(e) = super::RustLDAP::new("lda://localhost"){

			assert_eq!("Bad parameter to an ldap routine", e);

		} else {

			assert!(false);

		}

    }

    #[test]
    fn test_simple_bind(){

        let ldap = super::RustLDAP::new(TEST_ADDRESS).unwrap();
        let res = ldap.simple_bind(TEST_BIND_DN, TEST_BIND_PASS).unwrap();
        println!("{:?}", res);

    }

    #[test]
    fn test_simple_search(){

        println!("Testing simple search");
        let ldap = super::RustLDAP::new(TEST_ADDRESS).unwrap();
        let _ = ldap.simple_bind(TEST_BIND_DN, TEST_BIND_PASS).unwrap();
        let search_res = ldap.simple_search(TEST_SIMPLE_SEARCH_QUERY, codes::scopes::LDAP_SCOPE_BASE).unwrap();
		println!("{:?}", search_res);

    }

	#[test]
	fn test_search(){

		println!("Testing simple search");
        let ldap = super::RustLDAP::new(TEST_ADDRESS).unwrap();
        let _ = ldap.simple_bind(TEST_BIND_DN, TEST_BIND_PASS).unwrap();
        let search_res = ldap.ldap_search(TEST_SEARCH_BASE, codes::scopes::LDAP_SCOPE_SUB, Some(TEST_SEARCH_FILTER),
											None, false, None, None, ptr::null(), -1).unwrap();
		println!("{:?}", search_res);

	}

	#[test]
	fn test_search_attrs(){

		println!("Testing simple search");
		let test_search_attrs_vec = vec!["cn", "sn", "mail"];
		let ldap = super::RustLDAP::new(TEST_ADDRESS).unwrap();
		let _ = ldap.simple_bind(TEST_BIND_DN, TEST_BIND_PASS).unwrap();
		let search_res = ldap.ldap_search(TEST_SEARCH_BASE, codes::scopes::LDAP_SCOPE_SUB, Some(TEST_SEARCH_FILTER),
											Some(test_search_attrs_vec), false, None, None, ptr::null(), -1).unwrap();
		println!("{:?}", search_res);

	}

}
