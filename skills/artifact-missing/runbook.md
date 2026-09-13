# Artifact failures

Start from the failed downstream job, then inspect its upstream producer. Confirm that the producer ran, the artifact path matched, and job rules did not skip the producer. Do not replace an unavailable release artifact with a manually created file.
