package com.najman.springsecurity.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static com.najman.springsecurity.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()),
    TEACHER(Sets.newHashSet(COURSE_READ, COURSE_WRITE, STUDENT_READ)),
    ADMIN(Sets.newHashSet(COURSE_DELETE, COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE, STUDENT_DELETE));

    private final Set<ApplicationUserPermission> permissionsSet;

    ApplicationUserRole(Set<ApplicationUserPermission> permissionsSet) {
        this.permissionsSet = permissionsSet;
    }

    public Set<ApplicationUserPermission> getPermissionsSet() {
        return permissionsSet;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities(){
        Set<SimpleGrantedAuthority> permissions =  getPermissionsSet().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return permissions;
    }
}
