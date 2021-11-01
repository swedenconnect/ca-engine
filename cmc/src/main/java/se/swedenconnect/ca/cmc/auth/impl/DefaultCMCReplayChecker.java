/*
 * Copyright (c) 2021. Agency for Digital Government (DIGG)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.swedenconnect.ca.cmc.auth.impl;

import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.PKIData;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import se.swedenconnect.ca.cmc.api.data.CMCControlObjectID;
import se.swedenconnect.ca.cmc.auth.CMCReplayChecker;
import se.swedenconnect.ca.cmc.auth.CMCUtils;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Default implementation of a replay checker
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultCMCReplayChecker implements CMCReplayChecker {

  private static final Date startupTime;

  static {
    RuntimeMXBean runtimeMXBean = ManagementFactory.getRuntimeMXBean();
    startupTime = new Date(runtimeMXBean.getStartTime());
  }

  private List<ReplayData> nonceList = new ArrayList<>();
  long maxAgeMillis;
  long retentionMillis;
  long futureTimeSkewMillis;


  public DefaultCMCReplayChecker(int maxAgeSec, long retentionSec, long futureTimeSkewSec) {
    this.maxAgeMillis = 1000L * maxAgeSec;
    this.retentionMillis = 1000L * retentionSec;
    this.futureTimeSkewMillis = 1000L * futureTimeSkewSec;
    log.info("Replay checker created with system start time = {}, max age sec={}, retention sec={}, future time skew sec={}", startupTime, maxAgeSec, retentionSec, futureTimeSkewSec);
  }
  public DefaultCMCReplayChecker(int maxAgeSec, long retentionSec) {
    this (maxAgeSec, retentionSec, 60);
  }

  public DefaultCMCReplayChecker() {
    this(120, 200, 60);
  }

  @Override public void validate(CMSSignedData signedData) throws IOException {
    try {
      consolidateReplayData();
      PKIData pkiData = PKIData.getInstance(new ASN1InputStream((byte[]) signedData.getSignedContent().getContent()).readObject());
      Date messageTime = CMCUtils.getSigningTime(signedData);
      Date notBefore = new Date(System.currentTimeMillis() - maxAgeMillis);
      Date notAfter = new Date(System.currentTimeMillis() + futureTimeSkewMillis);
      if (messageTime == null){
        throw new IOException("Replay check failed: Message time is missing in CMC request");
      }
      if (messageTime.before(startupTime)){
        // We do not allow under any circumstances a message created before startup time as we have no knowledge of what happened before this instant.
        throw new IOException("Replay check failed: Request older than system startup time");
      }
      if (messageTime.before(notBefore)) {
        throw new IOException("Replay check failed: Request is to lod");
      }
      if (messageTime.after(notAfter)){
        throw new IOException("Replay check failed: Request time in future time");
      }
      byte[] nonce = (byte[]) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_senderNonce, pkiData).getValue();
      if (nonce == null){
        throw new IOException("Replay check failed: Request nonce is missing");
      }

      if (nonceList.stream().anyMatch(replayData -> Arrays.equals(nonce, replayData.getNonce()))){
        throw new IOException("Replay check failed: Replay of request nonce");
      }
      nonceList.add(new ReplayData (nonce, messageTime));

    } catch (Exception ex) {
      if (ex instanceof IOException){
        throw (IOException) ex;
      }
      throw new IOException("Error processing replay data - Replay check failed", ex);
    }
  }

  private void consolidateReplayData() {
    Date maxAge = new Date(System.currentTimeMillis() - retentionMillis);
    nonceList = nonceList.stream()
      .filter(replayData -> replayData.getMessageTime().after(maxAge))
      .collect(Collectors.toList());
  }

  @Getter
  @AllArgsConstructor
  public static class ReplayData {
    byte[] nonce;
    Date messageTime;
  }

}
