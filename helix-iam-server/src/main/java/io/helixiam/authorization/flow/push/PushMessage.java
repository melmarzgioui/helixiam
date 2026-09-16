package io.helixiam.authorization.flow.push;

import java.util.List;

/**
 * Helix IAM E4.3: a push-approval notification to deliver to a user's enrolled device(s). Carries
 * the approval id, the challenge the device must sign, and the number-matching choices the phone
 * shows (the user must tap {@code expectedNumber}). The transport (FCM/APNs) is a {@link PushSender}.
 */
public record PushMessage(String approvalId, String userId, String challenge,
                          int expectedNumber, List<Integer> candidates) {
}
