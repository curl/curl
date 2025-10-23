/***************************************************************************
 * Progress tracking for CurlDotNet
 *
 * Real-time progress reporting for downloads and uploads
 *
 * By Jacob Mellor
 * GitHub: https://github.com/jacob-mellor
 * Sponsored by Iron Software (ironsoftware.com)
 ***************************************************************************/

using System;

namespace CurlDotNet.Progress
{
    /// <summary>
    /// Progress information for curl operations
    /// </summary>
    public class CurlProgressInfo
    {
        /// <summary>
        /// Total bytes to transfer (download or upload)
        /// </summary>
        public long TotalBytes { get; set; }

        /// <summary>
        /// Bytes transferred so far
        /// </summary>
        public long TransferredBytes { get; set; }

        /// <summary>
        /// Total bytes for upload (when doing both upload and download)
        /// </summary>
        public long TotalUploadBytes { get; set; }

        /// <summary>
        /// Bytes uploaded so far
        /// </summary>
        public long UploadedBytes { get; set; }

        /// <summary>
        /// Percentage complete (0-100)
        /// </summary>
        public double PercentComplete => TotalBytes > 0
            ? (TransferredBytes * 100.0 / TotalBytes)
            : 0;

        /// <summary>
        /// Upload percentage complete (0-100)
        /// </summary>
        public double UploadPercentComplete => TotalUploadBytes > 0
            ? (UploadedBytes * 100.0 / TotalUploadBytes)
            : 0;

        /// <summary>
        /// Current transfer speed in bytes per second
        /// </summary>
        public double SpeedBytesPerSecond { get; set; }

        /// <summary>
        /// Average transfer speed in bytes per second
        /// </summary>
        public double AverageSpeedBytesPerSecond { get; set; }

        /// <summary>
        /// Time elapsed since transfer started
        /// </summary>
        public TimeSpan ElapsedTime { get; set; }

        /// <summary>
        /// Estimated time remaining
        /// </summary>
        public TimeSpan EstimatedTimeRemaining
        {
            get
            {
                if (SpeedBytesPerSecond > 0 && TotalBytes > TransferredBytes)
                {
                    var remainingBytes = TotalBytes - TransferredBytes;
                    var secondsRemaining = remainingBytes / SpeedBytesPerSecond;
                    return TimeSpan.FromSeconds(secondsRemaining);
                }
                return TimeSpan.Zero;
            }
        }

        /// <summary>
        /// Type of operation (Download, Upload, or Both)
        /// </summary>
        public ProgressOperation Operation { get; set; }

        /// <summary>
        /// Current status message
        /// </summary>
        public string Status { get; set; }

        /// <summary>
        /// URL being accessed
        /// </summary>
        public string Url { get; set; }

        /// <summary>
        /// Get human-readable speed string
        /// </summary>
        public string GetSpeedString()
        {
            return FormatBytes(SpeedBytesPerSecond) + "/s";
        }

        /// <summary>
        /// Get human-readable progress string
        /// </summary>
        public override string ToString()
        {
            if (Operation == ProgressOperation.Download)
            {
                return $"↓ {PercentComplete:F1}% ({FormatBytes(TransferredBytes)}/{FormatBytes(TotalBytes)}) at {GetSpeedString()} - ETA: {EstimatedTimeRemaining:mm\\:ss}";
            }
            else if (Operation == ProgressOperation.Upload)
            {
                return $"↑ {UploadPercentComplete:F1}% ({FormatBytes(UploadedBytes)}/{FormatBytes(TotalUploadBytes)}) at {GetSpeedString()} - ETA: {EstimatedTimeRemaining:mm\\:ss}";
            }
            else
            {
                return $"↓↑ D:{PercentComplete:F1}% U:{UploadPercentComplete:F1}% at {GetSpeedString()}";
            }
        }

        private static string FormatBytes(double bytes)
        {
            string[] sizes = { "B", "KB", "MB", "GB", "TB" };
            int order = 0;
            while (bytes >= 1024 && order < sizes.Length - 1)
            {
                order++;
                bytes /= 1024;
            }
            return $"{bytes:F2} {sizes[order]}";
        }
    }

    /// <summary>
    /// Type of progress operation
    /// </summary>
    public enum ProgressOperation
    {
        Download,
        Upload,
        Both
    }

    /// <summary>
    /// Progress bar renderer for console applications
    /// </summary>
    public class CurlProgressBar
    {
        private int _lastLineLength = 0;
        private readonly object _lock = new object();

        /// <summary>
        /// Render progress bar to console
        /// </summary>
        public void Render(CurlProgressInfo progress)
        {
            lock (_lock)
            {
                var barWidth = 30;
                var filledWidth = (int)(barWidth * progress.PercentComplete / 100);
                var emptyWidth = barWidth - filledWidth;

                var bar = new string('█', filledWidth) + new string('░', emptyWidth);
                var line = $"\r[{bar}] {progress.PercentComplete:F1}% - {progress.GetSpeedString()} - ETA: {progress.EstimatedTimeRemaining:mm\\:ss}";

                // Clear previous line if it was longer
                if (line.Length < _lastLineLength)
                {
                    Console.Write("\r" + new string(' ', _lastLineLength));
                }

                Console.Write(line);
                _lastLineLength = line.Length;
            }
        }

        /// <summary>
        /// Complete the progress bar
        /// </summary>
        public void Complete()
        {
            Console.WriteLine();
        }
    }
}