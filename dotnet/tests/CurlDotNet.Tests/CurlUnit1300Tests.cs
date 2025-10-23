using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using Xunit.Abstractions;
using FluentAssertions;

namespace CurlDotNet.Tests
{
    /// <summary>
    /// Port of curl's unit test 1300 - linked list operations.
    /// Since CurlDotNet uses .NET collections instead of custom linked lists,
    /// these tests verify equivalent collection operations.
    /// </summary>
    /// <remarks>
    /// <para>Original curl test: tests/unit/unit1300.c</para>
    /// <para>Tests list initialization, insertion, removal, and traversal.</para>
    /// <para>AI-Usage: These tests demonstrate collection management patterns used in CurlDotNet.</para>
    /// </remarks>
    [Trait("Category", TestCategories.CurlUnit)]
    [Trait("Category", TestCategories.Compatibility)]
    public class CurlUnit1300Tests : CurlTestBase
    {
        public CurlUnit1300Tests(ITestOutputHelper output) : base(output)
        {
            Output.WriteLine("Running curl unit test 1300 - Collection operations");
        }

        /// <summary>
        /// Test list initialization - equivalent to Curl_llist_init
        /// </summary>
        [Fact]
        public void TestListInitialization()
        {
            // Arrange & Act
            var list = new LinkedList<object>();

            // Assert - equivalent to curl's checks
            list.Should().NotBeNull("list should be initialized");
            list.Count.Should().Be(0, "initial list size should be zero");
            list.First.Should().BeNull("list head should be null initially");
            list.Last.Should().BeNull("list tail should be null initially");
        }

        /// <summary>
        /// Test inserting into empty list - equivalent to Curl_llist_insert_next on empty list
        /// </summary>
        [Fact]
        public void TestInsertIntoEmptyList()
        {
            // Arrange
            var list = new LinkedList<int>();
            var unusedData_case1 = 1;

            // Act - equivalent to Curl_llist_insert_next
            var node1 = list.AddLast(unusedData_case1);

            // Assert
            list.Count.Should().Be(1, "List size should be 1 after adding a new element");
            list.First.Should().NotBeNull("List head should not be null");
            list.First.Value.Should().Be(unusedData_case1, "head ptr should hold the data");
            list.Last.Should().Be(list.First, "tail and head should be the same");
        }

        /// <summary>
        /// Test inserting at head - equivalent to Curl_llist_insert_next at head
        /// </summary>
        [Fact]
        public void TestInsertAtHead()
        {
            // Arrange
            var list = new LinkedList<int>();
            var unusedData_case1 = 1;
            var unusedData_case2 = 2;

            // Act
            list.AddLast(unusedData_case1);
            var node2 = list.AddFirst(unusedData_case2); // Insert at head

            // Assert
            list.Count.Should().Be(2, "List size should be 2");
            list.First.Value.Should().Be(unusedData_case2, "New element should be at head");
            list.Last.Value.Should().Be(unusedData_case1, "Original element should be at tail");

            // Check linkage
            list.First.Next.Should().Be(list.Last);
            list.Last.Previous.Should().Be(list.First);
        }

        /// <summary>
        /// Test inserting at tail - equivalent to Curl_llist_insert_next at tail
        /// </summary>
        [Fact]
        public void TestInsertAtTail()
        {
            // Arrange
            var list = new LinkedList<int>();
            var unusedData_case1 = 1;
            var unusedData_case2 = 2;
            var unusedData_case3 = 3;

            // Act
            list.AddLast(unusedData_case1);
            list.AddLast(unusedData_case2);
            var node3 = list.AddLast(unusedData_case3);

            // Assert
            list.Count.Should().Be(3, "List should have 3 elements");
            list.Last.Value.Should().Be(unusedData_case3, "New element should be at tail");

            // Verify order
            var values = list.ToArray();
            values.Should().Equal(1, 2, 3);
        }

        /// <summary>
        /// Test removing from list - equivalent to Curl_llist_remove
        /// </summary>
        [Fact]
        public void TestRemoveFromList()
        {
            // Arrange
            var list = new LinkedList<int>();
            var values = new[] { 1, 2, 3, 4 };
            var nodes = new LinkedListNode<int>[4];

            for (int i = 0; i < values.Length; i++)
            {
                nodes[i] = list.AddLast(values[i]);
            }

            // Act - Remove middle element (like curl test removes case3)
            list.Remove(nodes[2]); // Remove value 3

            // Assert
            list.Count.Should().Be(3, "List should have 3 elements after removal");
            list.Should().NotContain(3, "Removed element should not be in list");
            list.ToArray().Should().Equal(1, 2, 4);

            // Check linkage is maintained
            nodes[1].Next.Should().Be(nodes[3]);
            nodes[3].Previous.Should().Be(nodes[1]);
        }

        /// <summary>
        /// Test removing head - equivalent to removing head node
        /// </summary>
        [Fact]
        public void TestRemoveHead()
        {
            // Arrange
            var list = new LinkedList<int>();
            list.AddLast(1);
            list.AddLast(2);
            list.AddLast(3);

            // Act
            list.RemoveFirst();

            // Assert
            list.Count.Should().Be(2);
            list.First.Value.Should().Be(2, "New head should be second element");
            list.ToArray().Should().Equal(2, 3);
        }

        /// <summary>
        /// Test removing tail - equivalent to removing tail node
        /// </summary>
        [Fact]
        public void TestRemoveTail()
        {
            // Arrange
            var list = new LinkedList<int>();
            list.AddLast(1);
            list.AddLast(2);
            list.AddLast(3);

            // Act
            list.RemoveLast();

            // Assert
            list.Count.Should().Be(2);
            list.Last.Value.Should().Be(2, "New tail should be second element");
            list.ToArray().Should().Equal(1, 2);
        }

        /// <summary>
        /// Test removing single element - list becomes empty
        /// </summary>
        [Fact]
        public void TestRemoveSingleElement()
        {
            // Arrange
            var list = new LinkedList<int>();
            var node = list.AddLast(42);

            // Act
            list.Remove(node);

            // Assert
            list.Count.Should().Be(0, "List should be empty");
            list.First.Should().BeNull("Head should be null");
            list.Last.Should().BeNull("Tail should be null");
        }

        /// <summary>
        /// Test list traversal - equivalent to iterating through curl's llist
        /// </summary>
        [Fact]
        public void TestListTraversal()
        {
            // Arrange
            var list = new LinkedList<int>();
            var expectedValues = new[] { 10, 20, 30, 40, 50 };

            foreach (var val in expectedValues)
            {
                list.AddLast(val);
            }

            // Act - Forward traversal
            var forwardValues = new List<int>();
            var current = list.First;
            while (current != null)
            {
                forwardValues.Add(current.Value);
                current = current.Next;
            }

            // Assert forward traversal
            forwardValues.Should().Equal(expectedValues);

            // Act - Backward traversal
            var backwardValues = new List<int>();
            current = list.Last;
            while (current != null)
            {
                backwardValues.Add(current.Value);
                current = current.Previous;
            }

            // Assert backward traversal
            backwardValues.Should().Equal(expectedValues.Reverse());
        }

        /// <summary>
        /// Test finding elements - equivalent to searching in curl's llist
        /// </summary>
        [Fact]
        public void TestFindElement()
        {
            // Arrange
            var list = new LinkedList<string>();
            list.AddLast("first");
            list.AddLast("second");
            list.AddLast("third");
            list.AddLast("second"); // Duplicate

            // Act
            var found = list.Find("second");
            var foundLast = list.FindLast("second");

            // Assert
            found.Should().NotBeNull();
            found.Value.Should().Be("second");
            found.Should().Be(list.First.Next, "Should find first occurrence");

            foundLast.Should().NotBeNull();
            foundLast.Value.Should().Be("second");
            foundLast.Should().Be(list.Last, "Should find last occurrence");
        }

        /// <summary>
        /// Test list clear - equivalent to destroying and reinitializing
        /// </summary>
        [Fact]
        public void TestListClear()
        {
            // Arrange
            var list = new LinkedList<int>();
            for (int i = 0; i < 10; i++)
            {
                list.AddLast(i);
            }

            // Act
            list.Clear();

            // Assert
            list.Count.Should().Be(0, "List should be empty after clear");
            list.First.Should().BeNull("Head should be null after clear");
            list.Last.Should().BeNull("Tail should be null after clear");
        }

        /// <summary>
        /// Test inserting after specific node
        /// </summary>
        [Fact]
        public void TestInsertAfter()
        {
            // Arrange
            var list = new LinkedList<int>();
            var node1 = list.AddLast(1);
            var node3 = list.AddLast(3);

            // Act
            var node2 = list.AddAfter(node1, 2);

            // Assert
            list.Count.Should().Be(3);
            list.ToArray().Should().Equal(1, 2, 3);
            node1.Next.Should().Be(node2);
            node2.Previous.Should().Be(node1);
            node2.Next.Should().Be(node3);
            node3.Previous.Should().Be(node2);
        }

        /// <summary>
        /// Test inserting before specific node
        /// </summary>
        [Fact]
        public void TestInsertBefore()
        {
            // Arrange
            var list = new LinkedList<int>();
            var node1 = list.AddLast(1);
            var node3 = list.AddLast(3);

            // Act
            var node2 = list.AddBefore(node3, 2);

            // Assert
            list.Count.Should().Be(3);
            list.ToArray().Should().Equal(1, 2, 3);
            node1.Next.Should().Be(node2);
            node2.Previous.Should().Be(node1);
            node2.Next.Should().Be(node3);
            node3.Previous.Should().Be(node2);
        }

        /// <summary>
        /// Test concurrent modifications safety
        /// This tests a common issue in C linked lists that .NET collections handle
        /// </summary>
        [Fact]
        public void TestConcurrentModificationDetection()
        {
            // Arrange
            var list = new LinkedList<int>();
            for (int i = 0; i < 5; i++)
            {
                list.AddLast(i);
            }

            // Act & Assert
            Action act = () =>
            {
                foreach (var item in list)
                {
                    if (item == 2)
                    {
                        list.Remove(item); // This will throw
                    }
                }
            };

            act.Should().Throw<InvalidOperationException>()
                .WithMessage("*modified*");
        }

        /// <summary>
        /// Test memory efficiency - verifies no memory leaks
        /// In C this would test proper free() calls, in .NET we verify GC behavior
        /// </summary>
        [Fact]
        public void TestMemoryManagement()
        {
            // Arrange
            WeakReference weakRef = null;

            // Act - Create list in separate scope
            void CreateList()
            {
                var list = new LinkedList<byte[]>();
                for (int i = 0; i < 100; i++)
                {
                    list.AddLast(new byte[1024]); // 1KB per node
                }
                weakRef = new WeakReference(list);
            }

            CreateList();

            // Force garbage collection
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            // Assert - List should be garbage collected
            weakRef.IsAlive.Should().BeFalse("List should be garbage collected when out of scope");
        }
    }
}