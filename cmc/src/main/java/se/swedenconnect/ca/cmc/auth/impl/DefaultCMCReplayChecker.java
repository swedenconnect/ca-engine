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
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.PKIData;
import se.swedenconnect.ca.cmc.api.data.CMCControlObjectID;
import se.swedenconnect.ca.cmc.auth.CMCReplayChecker;
import se.swedenconnect.ca.cmc.auth.CMCUtils;

import java.io.IOException;
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

  private List<ReplayData> nonceList = new ArrayList<>();
  long maxAgeMillis;
  long retentionMillis;
  long futureTimeSkewMillis;

  public DefaultCMCReplayChecker(int maxAgeSec, long retentionSec, long futureTimeSkewSec) {
    this.maxAgeMillis = 1000L * maxAgeSec;
    this.retentionMillis = 1000L * retentionSec;
    this.futureTimeSkewMillis = 1000L * futureTimeSkewSec;
  }
  public DefaultCMCReplayChecker(int maxAgeSec, long retentionSec) {
    this.maxAgeMillis = 1000L * maxAgeSec;
    this.retentionMillis = 1000L * retentionSec;
    this.futureTimeSkewMillis = 1000L * 60L;
  }

  public DefaultCMCReplayChecker() {
    this.maxAgeMillis = 1000L * 120L;
    this.retentionMillis = 1000L * 200L;
    this.futureTimeSkewMillis = 1000L * 60L;
  }

  @Override public void validate(PKIData pkiData) throws IOException {
    try {
      consolidateReplayData();
      Date messateTime = (Date) CMCUtils.getCMCControlObject(CMCControlObjectID.messageTime.getOid(), pkiData).getValue();
      Date notBefore = new Date(System.currentTimeMillis() - maxAgeMillis);
      Date notAfter = new Date(System.currentTimeMillis() + futureTimeSkewMillis);
      if (messateTime == null){
        throw new IOException("Replay check failed: Message time is missing in CMC request");
      }
      if (messateTime.before(notBefore)) {
        throw new IOException("Replay check failed: Request is to lod");
      }
      if (messateTime.after(notAfter)){
        throw new IOException("Replay check failed: Request time in future time");
      }
      byte[] nonce = (byte[]) CMCUtils.getCMCControlObject(CMCObjectIdentifiers.id_cmc_senderNonce, pkiData).getValue();
      if (nonce == null){
        throw new IOException("Replay check failed: Request nonce is missing");
      }

      if (nonceList.stream().anyMatch(replayData -> Arrays.equals(nonce, replayData.getNonce()))){
        throw new IOException("Replay check failed: Replay of request nonce");
      }
      nonceList.add(new ReplayData (nonce, messateTime));

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
