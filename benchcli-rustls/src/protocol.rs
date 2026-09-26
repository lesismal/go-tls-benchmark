//! benchcli-go/protocol: the messages go on the connection back to back with
//! nothing between them, so what is left is how BenchPipeline batches them
//! into writes and how it checks an echo that arrives in pieces.

/// protocol.BatchBuffers: as many copies of buf as fit in max_len, and at
/// least one, no more than rate - fewer if that many would not divide rate -
/// with that count and how many writes a second send rate copies a second.
pub fn batch_buffers(buf: &[u8], rate: usize, max_len: usize) -> (Vec<u8>, usize, usize) {
    let mut batch = (max_len / buf.len()).max(1).min(rate.max(1));
    while batch > 1 && rate % batch != 0 {
        batch -= 1;
    }
    (buf.repeat(batch), batch, rate / batch)
}

/// protocol.PipelineBuffers.
pub fn pipeline_buffers(buf: &[u8], rate: usize, pipeline: usize) -> (Vec<u8>, usize, usize) {
    (buf.repeat(pipeline), pipeline, rate / pipeline)
}

/// protocol.ValidatePipeline.
pub fn validate_pipeline(pipeline: i64, rate: usize) -> Result<(), String> {
    if pipeline < 0 {
        return Err(format!(
            "pipeline {pipeline}: want 0, which fits as many messages as -rbs holds, or more"
        ));
    }
    if pipeline > 0 && rate % pipeline as usize != 0 {
        return Err(format!(
            "pipeline {pipeline} does not divide the send rate {rate}, so no whole number of writes a second sends it; pick a divisor of {rate}"
        ));
    }
    Ok(())
}

/// protocol.MatchesRepeated: whether data is what a stream of msg repeated
/// end to end holds from offset bytes into one of its copies on.
pub fn matches_repeated(mut data: &[u8], msg: &[u8], offset: usize) -> bool {
    let mut offset = offset % msg.len();
    while !data.is_empty() {
        let n = data.len().min(msg.len() - offset);
        if data[..n] != msg[offset..offset + n] {
            return false;
        }
        data = &data[n..];
        offset = 0;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batches() {
        let msg = vec![b'x'; 1024];
        let (buf, batch, tick) = batch_buffers(&msg, 200, 16 << 10);
        assert_eq!((buf.len(), batch, tick), (10 * 1024, 10, 20));
        assert_eq!(batch_buffers(&msg, 40, 16 << 10).1, 10);
        assert_eq!(batch_buffers(&msg, 4, 16 << 10).1, 4);
        assert_eq!(batch_buffers(&msg, 7, 100).1, 1);
        assert_eq!(
            pipeline_buffers(b"ab", 200, 8),
            (b"abababababababab".to_vec(), 8, 25)
        );
        assert!(validate_pipeline(8, 200).is_ok() && validate_pipeline(0, 200).is_ok());
        assert!(validate_pipeline(3, 200).is_err() && validate_pipeline(-1, 200).is_err());
    }

    #[test]
    fn repeated() {
        let msg = b"0123456789";
        let stream = msg.repeat(5);
        for cut in [1, 3, 7, 10, 16, 50] {
            let mut offset = 0;
            for piece in stream.chunks(cut) {
                assert!(
                    matches_repeated(piece, msg, offset),
                    "cut {cut} at {offset}"
                );
                offset += piece.len();
            }
        }
        assert!(!matches_repeated(b"0123x", msg, 0));
        assert!(!matches_repeated(b"89012", msg, 7));
        assert!(matches_repeated(b"89012", msg, 18));
    }
}
