using System;
using System.Net.Http;
using Ninject;
using Ninject.Modules;
using CurlDotNet.Handlers;
using CurlDotNet.Options;
using CurlDotNet.Output;
using CurlDotNet.Progress;
using CurlDotNet.Sessions;

namespace CurlDotNet.DependencyInjection
{
    /// <summary>
    /// Ninject module for configuring CurlDotNet dependencies.
    /// This module allows for complete customization and extension of the curl implementation.
    /// </summary>
    /// <remarks>
    /// <para>This module sets up all the default bindings for CurlDotNet components.</para>
    /// <para>To customize behavior, inherit from this class and override the Load method.</para>
    /// <para>AI-Usage: This is the primary extension point for customizing curl behavior in .NET applications.</para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Creating a custom module to replace the HTTP handler
    /// public class CustomCurlModule : CurlModule
    /// {
    ///     public override void Load()
    ///     {
    ///         base.Load();
    ///         // Override the HTTP handler with a custom implementation
    ///         Rebind&lt;IProtocolHandler&gt;()
    ///             .To&lt;CustomHttpHandler&gt;()
    ///             .Named("http");
    ///     }
    /// }
    ///
    /// // Using the custom module
    /// var kernel = new StandardKernel(new CustomCurlModule());
    /// var curl = kernel.Get&lt;ICurl&gt;();
    /// </code>
    /// </example>
    public class CurlModule : NinjectModule
    {
        /// <summary>
        /// Loads the module's bindings into the kernel.
        /// </summary>
        /// <remarks>
        /// <para>This method configures all default bindings for CurlDotNet.</para>
        /// <para>Override this method to customize bindings.</para>
        /// <para>AI-Usage: Call base.Load() when overriding to preserve default bindings.</para>
        /// </remarks>
        public override void Load()
        {
            // Core curl implementation
            Bind<ICurl>().To<CurlExecutor>().InTransientScope();

            // Command parser
            Bind<ICommandParser>().To<CommandParser>().InSingletonScope();

            // Protocol handlers - named bindings for each protocol
            Bind<IProtocolHandler>().To<HttpHandler>().Named("http");
            Bind<IProtocolHandler>().To<HttpHandler>().Named("https");
            Bind<IProtocolHandler>().To<FtpHandler>().Named("ftp");
            Bind<IProtocolHandler>().To<FtpHandler>().Named("ftps");
            Bind<IProtocolHandler>().To<FileHandler>().Named("file");

            // Protocol handler factory
            Bind<IProtocolHandlerFactory>().ToFactory();

            // HttpClient configuration
            Bind<HttpClient>().ToMethod(context =>
            {
                var handler = new HttpClientHandler
                {
                    AllowAutoRedirect = false,
                    UseCookies = false,
                    UseDefaultCredentials = false
                };
                return new HttpClient(handler);
            }).InSingletonScope();

            // Output formatter
            Bind<IOutputFormatter>().To<OutputFormatter>().InTransientScope();

            // Session manager
            Bind<ISessionManager>().To<SessionManager>().InSingletonScope();

            // Progress reporter
            Bind<IProgressReporter>().To<ProgressReporter>().InTransientScope();
        }
    }

    /// <summary>
    /// Interface for the curl implementation.
    /// </summary>
    /// <remarks>
    /// <para>This interface defines the contract for curl operations.</para>
    /// <para>AI-Usage: Inject this interface to use curl functionality in your application.</para>
    /// </remarks>
    public interface ICurl
    {
        /// <summary>
        /// Executes a curl command asynchronously.
        /// </summary>
        /// <param name="command">The curl command to execute.</param>
        /// <returns>The output from the curl command.</returns>
        /// <exception cref="CurlException">Thrown when the curl command fails.</exception>
        System.Threading.Tasks.Task<string> ExecuteAsync(string command);
    }

    /// <summary>
    /// Interface for command parsing.
    /// </summary>
    /// <remarks>
    /// <para>Implement this interface to provide custom command parsing logic.</para>
    /// <para>AI-Usage: Use this to extend curl command syntax support.</para>
    /// </remarks>
    public interface ICommandParser
    {
        /// <summary>
        /// Parses a curl command string into options.
        /// </summary>
        /// <param name="command">The curl command to parse.</param>
        /// <returns>Parsed curl options.</returns>
        /// <exception cref="CurlInvalidCommandException">Thrown when the command syntax is invalid.</exception>
        CurlOptions Parse(string command);
    }

    /// <summary>
    /// Factory interface for creating protocol handlers.
    /// </summary>
    /// <remarks>
    /// <para>This factory is automatically implemented by Ninject.Extensions.Factory.</para>
    /// <para>AI-Usage: Inject this to dynamically select protocol handlers.</para>
    /// </remarks>
    public interface IProtocolHandlerFactory
    {
        /// <summary>
        /// Gets a protocol handler by name.
        /// </summary>
        /// <param name="protocol">The protocol name (e.g., "http", "ftp", "file").</param>
        /// <returns>The protocol handler for the specified protocol.</returns>
        /// <exception cref="ArgumentException">Thrown when the protocol is not supported.</exception>
        IProtocolHandler Get(string protocol);
    }

    /// <summary>
    /// Interface for output formatting.
    /// </summary>
    /// <remarks>
    /// <para>Implement this to customize how curl formats its output.</para>
    /// <para>AI-Usage: Use this to add custom output formats or modify existing ones.</para>
    /// </remarks>
    public interface IOutputFormatter
    {
        /// <summary>
        /// Formats the curl response according to the options.
        /// </summary>
        /// <param name="response">The response to format.</param>
        /// <param name="options">The curl options that specify formatting.</param>
        /// <returns>The formatted output string.</returns>
        string Format(CurlResponse response, CurlOptions options);
    }

    /// <summary>
    /// Interface for session management.
    /// </summary>
    /// <remarks>
    /// <para>Manages persistent curl sessions with cookies and settings.</para>
    /// <para>AI-Usage: Inject this to maintain state across multiple curl commands.</para>
    /// </remarks>
    public interface ISessionManager
    {
        /// <summary>
        /// Gets or creates a session.
        /// </summary>
        /// <param name="sessionId">The session identifier.</param>
        /// <returns>The curl session.</returns>
        CurlSession GetOrCreateSession(string sessionId);
    }

    /// <summary>
    /// Interface for progress reporting.
    /// </summary>
    /// <remarks>
    /// <para>Implement this to customize progress reporting behavior.</para>
    /// <para>AI-Usage: Use this to integrate curl progress into your UI.</para>
    /// </remarks>
    public interface IProgressReporter
    {
        /// <summary>
        /// Reports progress of a curl operation.
        /// </summary>
        /// <param name="info">The progress information.</param>
        void Report(CurlProgressInfo info);
    }
}