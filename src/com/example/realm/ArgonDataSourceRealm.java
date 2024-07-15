package com.example.realm;

import java.security.Principal;

import org.apache.catalina.realm.DataSourceRealm;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

public class ArgonDataSourceRealm extends DataSourceRealm {
	private final Argon2 argon2 = Argon2Factory.create();

	@Override
	public Principal authenticate(String username, String credentials) {
		var pass = getPassword(username);
		if (pass == null) {
			return null;
		}
		if (!argon2.verify(pass, credentials)) {
			return null;
		}
		return getPrincipal(username);
	}
}
