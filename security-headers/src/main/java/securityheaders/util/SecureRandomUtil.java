/*
 * Copyright 2015 Christopher Smith
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
package securityheaders.util;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SecureRandomUtil manages a SecureRandom instance and dispatches 
 * to it for requested values. The managed instance reseeds every so often
 *
 * @author Chris Smith
 *
 */
public class SecureRandomUtil {
	private static final Integer COUNTDOWN_MAX = 1000000;
	private static final Integer SEED_SIZE = 1024;

	private final SecureRandom random;
	private final AtomicInteger countdown; // when countdown reaches 0, reseed and reset countdown

	private static SecureRandomUtil instance = new SecureRandomUtil();

	private SecureRandomUtil() {
		this.random = new SecureRandom();
		generateNewSeed();
		this.countdown = new AtomicInteger(SecureRandomUtil.COUNTDOWN_MAX);
	}

	/**
	 * Reset the seed to a newly seeded value instead of constructing a new 
	 * object. This is cryptographically strong.
	 */
	private void generateNewSeed() {
		this.random.setSeed(this.random.generateSeed(SecureRandomUtil.SEED_SIZE));
	}

	/**
	 * After some number of uses of this instance, reseed the value <br/>
	 * Note: this method is thread-safe-<i>enough</i>. Several threads can 
	 * call it simultaneously, and more than one may reseed (which is 
	 * thread-safe). Therefore, the countdown is a good-enough pseudo-lock 
	 * to lower the likelihood of doing this operation twice, even though 
	 * there are no major downsides to doing the operation several times.
	 */
	private void checkReseed() {
		if (this.countdown.decrementAndGet() <= 0) {
			this.countdown.set(SecureRandomUtil.COUNTDOWN_MAX);
			generateNewSeed();
		}
	}

	/**
	 * Calls managed SecureRandom method
	 *
	 * @see SecureRandom#nextInt(int)
	 */
	public static int nextInt(int bound) {
		SecureRandomUtil.instance.checkReseed();
		return SecureRandomUtil.instance.random.nextInt(bound);
	}

	/**
	 * Generate a randomized String using the supplied parameters
	 * 
	 * @param options contains the Strings to choose from to generate the final string
	 * @param size the number of times to choose from options
	 * @return a string containing <b>size</b> number of <b>options</b> 
	 */
	public static String generateRandomString(String[] options, int size) {
		int len = options.length;

		StringBuilder sb = new StringBuilder(size);
		for (int i = 0; i < size; i++) {
			sb.append(options[nextInt(len)]);
		}

		return sb.toString();
	}

}
