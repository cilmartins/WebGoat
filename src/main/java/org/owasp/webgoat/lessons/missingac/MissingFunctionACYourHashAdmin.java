/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_ADMIN;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "access-control.hash.hint6",
  "access-control.hash.hint7",
  "access-control.hash.hint8",
  "access-control.hash.hint9",
  "access-control.hash.hint10",
  "access-control.hash.hint11",
  "access-control.hash.hint12",
  "access-control.hash.hint13"
})
public class MissingFunctionACYourHashAdmin implements AssignmentEndpoint {

  private final MissingAccessControlUserRepository userRepository;

  public MissingFunctionACYourHashAdmin(MissingAccessControlUserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @PostMapping(
      path = "/access-control/user-hash-fix",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult admin(String userHash) {
    // current user should be in the DB
    // if not admin then return 403

    var user = userRepository.findByUsername("Jerry");
    var displayUser = new DisplayUser(user, PASSWORD_SALT_ADMIN);
    // constant-time comparison of the secret hash to avoid timing side channels
    if (MessageDigest.isEqual(
        userHash.getBytes(StandardCharsets.UTF_8),
        displayUser.getUserHash().getBytes(StandardCharsets.UTF_8))) {
      return success(this).feedback("access-control.hash.success").build();
    } else {
      return failed(this).feedback("access-control.hash.close").build();
    }
  }
}
