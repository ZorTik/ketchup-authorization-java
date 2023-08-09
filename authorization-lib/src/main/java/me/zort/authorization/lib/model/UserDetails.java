package me.zort.authorization.lib.model;

import java.util.List;

public record UserDetails(boolean permissionsIncluded, List<String> permissions, String uuid, String primaryGroup, String username) { }
