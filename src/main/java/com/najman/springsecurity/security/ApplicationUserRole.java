package com.najman.springsecurity.security;

import com.google.common.collect.Sets;

import java.util.Set;

import static com.najman.springsecurity.security.ApplicationUserPermissions.*;

public enum ApplicationUserRole {
    STUDENT(Sets.newHashSet()),
    TEACHER(Sets.newHashSet(COURSE_READ, STUDENT_READ, STUDENT_WRITE)),
    ADMIN(Sets.newHashSet(COURSE_DELETE, COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE));

    private final Set<ApplicationUserPermissions> permissionsSet;

    ApplicationUserRole(Set<ApplicationUserPermissions> permissionsSet) {
        this.permissionsSet = permissionsSet;
    }

    public Set<ApplicationUserPermissions> getPermissionsSet() {
        return permissionsSet;
    }
}
